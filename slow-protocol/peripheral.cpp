//
//  peripheral.cpp – cliente “peripheral” do protocolo SLOW
//

// Este arquivo implementa a lógica do cliente "peripheral" (periférico)
// que se conecta a um servidor "central" usando o protocolo SLOW.
// Ele gerencia a conexão e o envio de dados, alem do  estado para funcionalidade de "revive".

#include "session.hpp"     // Inclui a classe Session, que gerencia a lógica do protocolo.
#include <arpa/inet.h>     // Para funções de conversão de endereço de rede (inet_ntoa).
#include <fstream>         // Para manipulação de arquivos (leitura/escrita de estado e mensagem).
#include <getopt.h>        // Para análise de argumentos de linha de comando (getopt_long).
#include <iomanip>         // Para formatação de saída.
#include <iostream>        // Para entrada/saída padrão.
#include <map>             // Para std::map, usado na remontagem de fragmentos (mantém ordem).
#include <netdb.h>         // Para getaddrinfo, para resolução de nomes de host.
#include <poll.h>          // Para poll, para monitorar eventos de socket (leitura disponível).
#include <unordered_map>   // Para std::unordered_map, usado na remontagem de fragmentos (por fid).

using namespace slow; // Usa o namespace slow para evitar prefixar tudo com slow::

// Constantes para o servidor padrão.
constexpr uint16_t PORT = 7033;
constexpr char     HOST[] = "slow.gmelodie.com";

/*──────── socket helpers ─────────*/
// Resolve um hostname para um endereço IPv4 (sockaddr_in).
static sockaddr_in resolve(const char* h) {
    addrinfo hints{}, *res;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;  
    // Chama getaddrinfo para resolver o hostname.
    if (getaddrinfo(h, nullptr, &hints, &res)) { perror("getaddrinfo"); exit(1); }
    sockaddr_in s = *reinterpret_cast<sockaddr_in*>(res->ai_addr); // Copia o endereço.
    s.sin_port    = htons(PORT);
    freeaddrinfo(res);
    return s;
}

// Cria um socket UDP e o conecta a um endereço remoto.
static int make_sock(const sockaddr_in& s, int to_ms) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); exit(1); }
    timeval tv{to_ms / 1000, (to_ms % 1000) * 1000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        // Conecta o socket ao endereço remoto.
    if (connect(fd, reinterpret_cast<const sockaddr*>(&s), sizeof(s)) < 0) {
        perror("connect"); exit(1);
    }
    return fd;
}

/*──────── Fragment reassembly helper ────────*/
// Estrutura para auxiliar na remontagem de fragmentos de dados.
struct FragBuf {
     // Mapa que armazena as partes do fragmento, indexadas pelo Fragment Offset (fo).
    // Garante que os fragmentos são armazenados em ordem.
    std::map<uint8_t, std::vector<uint8_t>> parts;
    bool   last = false;
    uint8_t max  = 0; // O maior Fragment Offset esperado (último fragmento).
    std::vector<uint8_t> finish() {
         // Só retorna o payload completo se:
        // 1. O último fragmento foi recebido (last == true).
        // 2. O número de partes recebidas é igual ao número total de partes esperadas (max + 1).
        if (!last || parts.size() != static_cast<size_t>(max + 1)) return {};
        std::vector<uint8_t> all;
        for (uint8_t i = 0; i <= max; ++i)
            all.insert(all.end(), parts[i].begin(), parts[i].end());
        return all;
    }
};

/*──────── state on disk ─────────*/
// Estrutura para salvar/carregar o estado da sessão em disco.
// Usado para a funcionalidade "revive".
struct StateDisk {
    UUID     sid;        uint32_t sttl{};
    uint32_t next_seq{}; uint32_t last_ack{};
    // Salva o estado da sessão em um arquivo binário.
    bool save(const std::string& p) {
        std::ofstream f(p, std::ios::binary); if (!f) return false;
        f.write(reinterpret_cast<char*>(sid.bytes.data()), 16);
        f.write(reinterpret_cast<char*>(&sttl),     4);
        f.write(reinterpret_cast<char*>(&next_seq), 4);
        f.write(reinterpret_cast<char*>(&last_ack), 4);
        return true;
    }
    // Carrega o estado da sessão de um arquivo binário.
    bool load(const std::string& p) {
        std::ifstream f(p, std::ios::binary); if (!f) return false;
        f.read(reinterpret_cast<char*>(sid.bytes.data()), 16);
        f.read(reinterpret_cast<char*>(&sttl),     4);
        f.read(reinterpret_cast<char*>(&next_seq), 4);
        f.read(reinterpret_cast<char*>(&last_ack), 4);
        return true;
    }
};

/*──────────────────────────────────────────────────────────────────*/
// Função auxiliar para imprimir detalhes de um pacote (útil para depuração).
static void dump_packet(const char* dir, const char* tag,
                        const Packet& p, std::size_t raw_sz) {
    std::cout << "\n" << dir << " " << tag << " seq=" << p.seqnum
              << " (" << raw_sz << "B)\n" << p;
}

/*──────────────── helper para fluxo de send/recv ────────────────*/
// Função principal que gerencia o loop de envio e recebimento de pacotes durante uma sessão SLOW ativa.
static void drive_session(int sock, Session& sess,
                          bool& waiting_dc_ack,
                          const std::string& fsave,
                          int rto) {

    pollfd pfd{sock, POLLIN, 0};
    std::unordered_map<uint8_t, FragBuf> reasm;

    auto tx = [&](const Packet& p, const char* tag) {
        auto raw = p.serialize();
        send(sock, raw.data(), raw.size(), 0);
        dump_packet("»»", tag, p, raw.size());
    };

    while (true) {
        // 1. Fase de Envio: Verifica e envia/retransmite pacotes da fila.
        for (auto* ob : sess.ready_to_send(rto)) {
            const char* tag = "DATA/FRAG";
            if (ob->first_sent.time_since_epoch().count() != 0) {
                tag = "RETX";
            } else if (ob->pkt.flags & FLAG_REVIVE) {
                tag = "REVIVE";
            }
            tx(ob->pkt, tag);

            if (ob->first_sent.time_since_epoch().count() == 0)
                ob->first_sent = std::chrono::steady_clock::now();
            sess.mark_sent(ob);
        }
// 2. Lógica de Desconexão: Se não há mais pacotes para enviar e ainda não está esperando o ACK de desconexão.
        if (!waiting_dc_ack && sess.empty()) {
            Packet d{};
            d.sid    = sess.sid();
            d.sttl   = sess.sttl();
            d.flags  = FLAG_CONNECT | FLAG_REVIVE | FLAG_ACK;
            d.seqnum = sess.take_seq();
            d.acknum = sess.last_rx_seq();
            d.window = 0;
            tx(d, "DISCONNECT");
            waiting_dc_ack = true;
        }
// 3. Fase de Recebimento: Usa `poll` para esperar por dados no socket com um timeout de 100ms.
        int r = poll(&pfd, 1, 100);
        if (r > 0 && (pfd.revents & POLLIN)) {
            uint8_t buf[2048];
            ssize_t n = recv(sock, buf, sizeof(buf), 0);
            if (n <= 0) continue;
            Packet pk = Packet::deserialize(buf, n);
            dump_packet("««", "RX", pk, n);

            sess.note_rx_seq(pk.seqnum);
            if (pk.flags & FLAG_ACK)
                sess.handle_ack(pk.acknum, pk.window, pk.sttl);
// Lógica para finalizar a sessão se estiver esperando o ACK de desconexão e o pacote recebido for um ACK que confirma o pacote de desconexão.
            if (waiting_dc_ack && (pk.flags & FLAG_ACK) && pk.seqnum == sess.last_ack()) {
                if (!fsave.empty()) {
                    StateDisk sd{sess.sid(), sess.sttl(), sess.peek_next_seq(), sess.last_rx_seq()};
                    sd.save(fsave);
                    std::cout << "[estado salvo em " << fsave << "]\n";
                }
                break;
            }

            if (!pk.data.empty()) {
                sess.consume_local_window(pk.data.size());
                auto& fb = reasm[pk.fid];
                fb.parts[pk.fo] = pk.data;
                if (!(pk.flags & FLAG_MOREBITS)) { fb.last = true; fb.max = pk.fo; }
                auto all = fb.finish();
                if (!all.empty()) {
                    std::cout << "\n### PAYLOAD (" << all.size() << "B) ###\n";
                    for (char c : all) std::cout << c;
                    std::cout << "\n################################\n";
                    reasm.erase(pk.fid);
                    sess.release_local_window(all.size());
                }
                // Envia um ACK "puro" (sem dados) para confirmar o recebimento do pacote de dados.
                Packet ack{};
                ack.sid    = sess.sid();
                ack.sttl   = sess.sttl();
                ack.flags  = FLAG_ACK;
                ack.seqnum = ack.acknum = pk.seqnum;
                ack.window = sess.local_window_left();
                tx(ack, "ACK-PURE");
            }
        }
    }
}

/*──────────────────────────────────────────────────────────────────*/
// Inicia uma nova conexão SLOW.
static void run_connect(int sock, int rto, const std::string& fsave,
                        const std::vector<uint8_t>& payload) {
    Session sess;
    bool waiting_dc_ack = false;

    Packet conn{};
    conn.flags  = FLAG_CONNECT;
    conn.window = sess.local_window_left();
    auto raw_conn = conn.serialize();
    send(sock, raw_conn.data(), raw_conn.size(), 0);
    dump_packet("»»", "CONNECT", conn, raw_conn.size());
// Espera pelo pacote SETUP do servidor.
    uint8_t buf[64];
    ssize_t n = recv(sock, buf, sizeof(buf), 0);
    if (n <= 0) { std::cerr << "timeout na recepção do SETUP\n"; exit(1); }
    Packet setup = Packet::deserialize(buf, n);
    dump_packet("««", "SETUP", setup, n);
// Verifica se a conexão foi aceita.
    if (!(setup.flags & FLAG_ACCEPT)) { std::cerr << "Conexão rejeitada (REJECT)\n"; exit(1); }
    sess.establish(setup);
    sess.note_rx_seq(setup.seqnum);
    if (!payload.empty()) {
        sess.queue_data(payload);
    }

    drive_session(sock, sess, waiting_dc_ack, fsave, rto);
}

/*──────────────────────────────────────────────────────────────────*/
// Tenta reviver uma sessão SLOW existente.
static void run_revive(int sock, int rto,
                       const std::string& fstate, const std::string& fsave,
                       const std::vector<uint8_t>& payload) {
    StateDisk sd;
    if (!sd.load(fstate)) {
        std::cerr << "estado revive inválido ou não encontrado em '" << fstate << "'\n";
        exit(1);
    }

    Session sess;
    Packet placeholder_for_establish;
    placeholder_for_establish.sid     = sd.sid;
    placeholder_for_establish.sttl    = sd.sttl;
    placeholder_for_establish.seqnum  = sd.next_seq - 1;
    placeholder_for_establish.acknum  = sd.last_ack;
    placeholder_for_establish.window  = 0;
    
    sess.establish(placeholder_for_establish);
    sess.note_rx_seq(sd.last_ack);
    
    sess.queue_data(payload, true);

    bool waiting_dc_ack = false;
    drive_session(sock, sess, waiting_dc_ack, fsave, rto);
}

/*──────────────────────────────────────────────────────────────────*/
// Função principal do programa.
int main(int argc, char* argv[]) {
    std::string fmsg, fstate, fsave;
    bool revive = false; // Flag para indicar se é uma operação de revive
    int  rto = 800, rcvto = 1500;
     // Opções de linha de comando usando getopt_long.
    option longopts[] = {
        {"msg", 1, 0, 'm'}, {"revive", 1, 0, 'r'}, {"save", 1, 0, 's'},
        {"rto", 1, 0, 't'},  {"recvto", 1, 0, 'T'}, {0, 0, 0, 0}};

    int opt, idx;
     // Loop para processar os argumentos da linha de comando.
    while ((opt = getopt_long(argc, argv, "m:r:s:t:T:", longopts, &idx)) != -1) {
        if      (opt == 'm') fmsg   = optarg;
        else if (opt == 'r') { fstate = optarg; revive = true; }
        else if (opt == 's') fsave  = optarg;
        else if (opt == 't') rto    = std::stoi(optarg);
        else if (opt == 'T') rcvto  = std::stoi(optarg);
        else {
            std::cerr << "uso: ./slowclient [--msg F] [--save F] [--revive F]\n";
            return 1;
        }
    }

    std::vector<uint8_t> payload; // Vetor para armazenar o payload a ser enviado.
    if (!fmsg.empty()) {
        std::ifstream f(fmsg, std::ios::binary);
        if (!f) { std::cerr << "Não foi possível abrir o arquivo de mensagem: " << fmsg << "\n"; return 1; }
        payload.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    } else if (!revive) {
        const char* default_msg = "Hello\n";
        payload.assign(default_msg, default_msg + strlen(default_msg));
    }

    int sock = make_sock(resolve(HOST), rcvto); // Cria e conecta o socket ao servidor.

    if (revive)
        run_revive(sock, rto, fstate, fsave, payload); // Inicia a sessão em modo revive.
    else
        run_connect(sock, rto, fsave, payload);  // Inicia uma nova conexão.

    return 0;
}