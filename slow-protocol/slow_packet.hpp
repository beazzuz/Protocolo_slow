#pragma once
//
//  slow_packet.hpp  –  Estruturas e utilidades do protocolo SLOW
// Este arquivo define as estruturas de dados fundamentais e utilidades
// para o protocolo de rede SLOW, incluindo a definição de pacotes e
// a lógica para serialização/desserialização.
#include <array>     // Para std::array, usado no UUID.
#include <cctype>    // Para std::isprint, usado na impressão de dados.
#include <cstdint>   // Para tipos inteiros de largura fixa (uint8_t, uint16_t, uint32_t).
#include <cstring>   // Para std::memcpy, usado na desserialização.
#include <iomanip>   // Para std::setw e std::setfill, usados na formatação de saída.
#include <iostream>  // Para std::ostream, usado na impressão.
#include <stdexcept> // Para std::runtime_error, usado em validações.
#include <vector>    // Para std::vector, usado para o payload do pacote.

namespace slow {

// ───────────────────── UUID v8 (wrapper simples) ─────────────────────
// Estrutura para representar um UUID (Universally Unique Identifier).
// É um identificador de 16 bytes, usado para identificar sessões
struct UUID {
    std::array<uint8_t, 16> bytes{};

    void clear() { bytes.fill(0); }

    void print(std::ostream& os = std::cout) const {
        auto f = os.flags();
        os << std::hex << std::setfill('0');
        for (int i = 0; i < 16; ++i) {
            os << std::setw(2) << static_cast<int>(bytes[i]);
            if (i == 3 || i == 5 || i == 7 || i == 9) os << '-';
        }
        os.flags(f);
    }
};

// ─────────────────────────── Flags ───────────────────────────
// Enumeração anônima para definir as flags do cabeçalho do protocolo SLOW.
// Cada flag é um bit específico dentro de um byte.
enum : uint8_t {
    FLAG_CONNECT   = 1u << 4,  // C
    FLAG_REVIVE    = 1u << 3,  // R
    FLAG_ACK       = 1u << 2,  // ACK
    FLAG_ACCEPT    = 1u << 1,  // A (1 = accept; 0 = reject)
    FLAG_MOREBITS  = 1u << 0   // MB
};

// ────────────────────────── Packet ──────────────────────────
// Estrutura que representa um pacote do protocolo SLOW.
// Contém o cabeçalho e o payload (dados).
struct Packet {
    UUID      sid;
    uint32_t  sttl   = 0;  // 27 bits
    uint8_t   flags  = 0;  // 5 bits
    uint32_t  seqnum = 0;
    uint32_t  acknum = 0;
    uint16_t  window = 0;
    uint8_t   fid    = 0;
    uint8_t   fo     = 0;
    std::vector<uint8_t> data;  // ≤ 1440 B

    // ───── serialização ─────────────────────────────────────
     // Converte a estrutura Packet em um vetor de bytes para transmissão pela rede.
    std::vector<uint8_t> serialize() const {
        if (data.size() > 1440)
            throw std::runtime_error("payload > 1440 bytes");

        std::vector<uint8_t> v;
        v.reserve(16 + 4 + 4 + 4 + 2 + 1 + 1 + data.size());

        // sid
        v.insert(v.end(), sid.bytes.begin(), sid.bytes.end());

        // flags|sttl (little-endian): Combina o STTL (27 bits) e as flags (5 bits) em um uint32_t.
        // O STTL é deslocado 5 bits para a esquerda para dar espaço às flags nos bits menos significativos.
        uint32_t flags_sttl = ((sttl & 0x07FFFFFFu) << 5) | (flags & 0x1Fu);
        append32le(v, flags_sttl);

        append32le(v, seqnum);
        append32le(v, acknum);
        append16le(v, window);
        v.push_back(fid);
        v.push_back(fo);

        v.insert(v.end(), data.begin(), data.end());
        return v;
    }

    // ───── desserialização ──────────────────────────────────
     // Converte um array de bytes recebido da rede de volta para a estrutura Packet.
    static Packet deserialize(const uint8_t* buf, size_t len) {
        constexpr size_t MIN = 16 + 4 + 4 + 4 + 2 + 1 + 1;
        if (len < MIN) throw std::runtime_error("pacote curto");

        Packet p;
        std::memcpy(p.sid.bytes.data(), buf, 16);
        size_t off = 16;

        uint32_t flags_sttl = read32le(buf + off); off += 4;
        p.flags = flags_sttl & 0x1Fu;
        p.sttl  = flags_sttl >> 5;

        p.seqnum = read32le(buf + off); off += 4;
        p.acknum = read32le(buf + off); off += 4;
        p.window = read16le(buf + off); off += 2;
        p.fid    = buf[off++];
        p.fo     = buf[off++];

         // Copia os dados restantes do buffer para o payload do pacote.
        p.data.assign(buf + off, buf + len);
        return p; // Retorna o Packet desserializado.
    }

private:
 // Funções auxiliares para adicionar inteiros em formato little-endian a um vetor de bytes.
    static void append16le(std::vector<uint8_t>& v, uint16_t x) {
        v.push_back(static_cast<uint8_t>(x));
        v.push_back(static_cast<uint8_t>(x >> 8));
    }
    static void append32le(std::vector<uint8_t>& v, uint32_t x) {
        v.push_back(static_cast<uint8_t>(x));
        v.push_back(static_cast<uint8_t>(x >> 8));
        v.push_back(static_cast<uint8_t>(x >> 16));
        v.push_back(static_cast<uint8_t>(x >> 24));
    }
    static uint16_t read16le(const uint8_t* p) {
        return static_cast<uint16_t>(p[0]) |
               static_cast<uint16_t>(p[1]) << 8;
    }
    static uint32_t read32le(const uint8_t* p) {
        return static_cast<uint32_t>(p[0])        |
              (static_cast<uint32_t>(p[1]) << 8)  |
              (static_cast<uint32_t>(p[2]) << 16) |
              (static_cast<uint32_t>(p[3]) << 24);
    }
};

// ─────────── pretty-print para std::ostream ───────────
// Sobrecarga do operador << para permitir a impressão fácil de um objeto Packet.
inline std::ostream& operator<<(std::ostream& os, const Packet& p)
{
    auto f = os.flags();
    os << std::hex << std::setfill('0');
// Imprime o SID.
    // sid
    os << "sid      : "; p.sid.print(os); os << '\n';
// Imprime as flags em hexadecimal e, em seguida, os valores binários de cada flag.
    // flags
    os << "flags    : 0x" << std::setw(2) << static_cast<int>(p.flags)
       << "  (C="  << ((p.flags & FLAG_CONNECT  ) ? '1' : '0')
       << ",R="    << ((p.flags & FLAG_REVIVE   ) ? '1' : '0')
       << ",ACK="  << ((p.flags & FLAG_ACK      ) ? '1' : '0')
       << ",A="    << ((p.flags & FLAG_ACCEPT   ) ? '1' : '0')
       << ",MB="   << ((p.flags & FLAG_MOREBITS ) ? '1' : '0') << ")\n";

    os << std::dec
       << "sttl(ms) : " << p.sttl   << '\n'
       << "seqnum   : " << p.seqnum << '\n'
       << "acknum   : " << p.acknum << '\n'
       << "window   : " << p.window << '\n'
       << "fid      : " << static_cast<int>(p.fid) << '\n'
       << "fo       : " << static_cast<int>(p.fo)  << '\n'
       << "data(len): " << p.data.size() << " B";

    if (!p.data.empty()) {
        const size_t PREVIEW = 64;
        os << "  → \"";
        for (size_t i = 0; i < std::min(p.data.size(), PREVIEW); ++i)
            os << (std::isprint(p.data[i]) ? static_cast<char>(p.data[i]) : '.');
        if (p.data.size() > PREVIEW) os << "…";
        os << '"';
    }
    os << '\n';
    os.flags(f); // Restaura as flags de formatação.
    return os;
}

} // namespace slow
