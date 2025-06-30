#pragma once
//
//  slow_packet.hpp  –  Estruturas e utilidades do protocolo SLOW
//
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace slow {

// ───────────────────── UUID v8 (wrapper simples) ─────────────────────
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
enum : uint8_t {
    FLAG_CONNECT   = 1u << 4,  // C
    FLAG_REVIVE    = 1u << 3,  // R
    FLAG_ACK       = 1u << 2,  // ACK
    FLAG_ACCEPT    = 1u << 1,  // A (1 = accept; 0 = reject)
    FLAG_MOREBITS  = 1u << 0   // MB
};

// ────────────────────────── Packet ──────────────────────────
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
    std::vector<uint8_t> serialize() const {
        if (data.size() > 1440)
            throw std::runtime_error("payload > 1440 bytes");

        std::vector<uint8_t> v;
        v.reserve(16 + 4 + 4 + 4 + 2 + 1 + 1 + data.size());

        // sid
        v.insert(v.end(), sid.bytes.begin(), sid.bytes.end());

        // flags|sttl (little-endian)
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

        p.data.assign(buf + off, buf + len);
        return p;
    }

private:
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
inline std::ostream& operator<<(std::ostream& os, const Packet& p)
{
    auto f = os.flags();
    os << std::hex << std::setfill('0');

    // sid
    os << "sid      : "; p.sid.print(os); os << '\n';

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
    os.flags(f);
    return os;
}

} // namespace slow
