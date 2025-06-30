//
//  peripheral.cpp – cliente “peripheral” do protocolo SLOW
//
#include "session.hpp"
#include <arpa/inet.h>
#include <fstream>
#include <getopt.h>
#include <iomanip>
#include <iostream>
#include <map>
#include <netdb.h>
#include <poll.h>
#include <unordered_map>

using namespace slow;

constexpr uint16_t PORT = 7033;
constexpr char     HOST[] = "slow.gmelodie.com";

/*──────── socket helpers ─────────*/
static sockaddr_in resolve(const char* h) {
    addrinfo hints{}, *res;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(h, nullptr, &hints, &res)) { perror("getaddrinfo"); exit(1); }
    sockaddr_in s = *reinterpret_cast<sockaddr_in*>(res->ai_addr);
    s.sin_port    = htons(PORT);
    freeaddrinfo(res);
    return s;
}
static int make_sock(const sockaddr_in& s, int to_ms) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); exit(1); }
    timeval tv{to_ms / 1000, (to_ms % 1000) * 1000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (connect(fd, reinterpret_cast<const sockaddr*>(&s), sizeof(s)) < 0) {
        perror("connect"); exit(1);
    }
    return fd;
}

/*──────── Fragment reassembly helper ────────*/
struct FragBuf {
    std::map<uint8_t, std::vector<uint8_t>> parts;
    bool   last = false;
    uint8_t max  = 0;
    std::vector<uint8_t> finish() {
        if (!last || parts.size() != static_cast<size_t>(max + 1)) return {};
        std::vector<uint8_t> all;
        for (uint8_t i = 0; i <= max; ++i)
            all.insert(all.end(), parts[i].begin(), parts[i].end());
        return all;
    }
};

/*──────── state on disk ─────────*/
struct StateDisk {
    UUID     sid;        uint32_t sttl{};
    uint32_t next_seq{}; uint32_t last_ack{};
    bool save(const std::string& p) {
        std::ofstream f(p, std::ios::binary); if (!f) return false;
        f.write(reinterpret_cast<char*>(sid.bytes.data()), 16);
        f.write(reinterpret_cast<char*>(&sttl),     4);
        f.write(reinterpret_cast<char*>(&next_seq), 4);
        f.write(reinterpret_cast<char*>(&last_ack), 4);
        return true;
    }
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
static void dump_packet(const char* dir, const char* tag,
                        const Packet& p, std::size_t raw_sz) {
    std::cout << "\n" << dir << " " << tag << " seq=" << p.seqnum
              << " (" << raw_sz << "B)\n" << p;
}

/*──────────────── helper para fluxo de send/recv ────────────────*/
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

    uint8_t buf[64];
    ssize_t n = recv(sock, buf, sizeof(buf), 0);
    if (n <= 0) { std::cerr << "timeout na recepção do SETUP\n"; exit(1); }
    Packet setup = Packet::deserialize(buf, n);
    dump_packet("««", "SETUP", setup, n);

    if (!(setup.flags & FLAG_ACCEPT)) { std::cerr << "Conexão rejeitada (REJECT)\n"; exit(1); }
    sess.establish(setup);
    sess.note_rx_seq(setup.seqnum);
    if (!payload.empty()) {
        sess.queue_data(payload);
    }

    drive_session(sock, sess, waiting_dc_ack, fsave, rto);
}

/*──────────────────────────────────────────────────────────────────*/
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
int main(int argc, char* argv[]) {
    std::string fmsg, fstate, fsave;
    bool revive = false;
    int  rto = 800, rcvto = 1500;
    option longopts[] = {
        {"msg", 1, 0, 'm'}, {"revive", 1, 0, 'r'}, {"save", 1, 0, 's'},
        {"rto", 1, 0, 't'},  {"recvto", 1, 0, 'T'}, {0, 0, 0, 0}};

    int opt, idx;
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

    std::vector<uint8_t> payload;
    if (!fmsg.empty()) {
        std::ifstream f(fmsg, std::ios::binary);
        if (!f) { std::cerr << "Não foi possível abrir o arquivo de mensagem: " << fmsg << "\n"; return 1; }
        payload.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    } else if (!revive) {
        const char* default_msg = "Hello\n";
        payload.assign(default_msg, default_msg + strlen(default_msg));
    }

    int sock = make_sock(resolve(HOST), rcvto);

    if (revive)
        run_revive(sock, rto, fstate, fsave, payload);
    else
        run_connect(sock, rto, fsave, payload);

    return 0;
}