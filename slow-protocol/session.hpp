#pragma once
//
//  session.hpp – lógica de janelas, filas e estatísticas do SLOW
//
#include "slow_packet.hpp"
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>

namespace slow {

struct Outbound {
    Packet pkt;
    std::chrono::steady_clock::time_point first_sent{};
    std::chrono::steady_clock::time_point last_sent{};
};

class Session {
public:
    explicit Session(uint16_t local_window = 65535)
        : sid_{},
          sttl_ms_(0),
          next_seq_(0),
          last_ack_rcvd_(0),
          local_window_(local_window),
          window_remote_(0),
          next_fid_(1),
          last_rx_seq_(0) {}

    /*──── fase de SETUP ou REVIVE ────*/
    void establish(const Packet& setup) {
        sid_          = setup.sid;
        sttl_ms_      = setup.sttl;
        next_seq_     = setup.seqnum + 1;
        window_remote_= setup.window;
        last_ack_rcvd_ = setup.acknum;
        start_        = std::chrono::steady_clock::now();
    }

    /*──── utilidades ────*/
    uint32_t take_seq()              { return next_seq_++; }
    uint32_t peek_next_seq()   const { return next_seq_;   }
    uint32_t last_ack()       const  { return last_ack_rcvd_; }
    uint16_t local_window_left()const{ return local_window_;  }
    const UUID& sid()         const  { return sid_; }
    uint32_t  sttl()          const  { return sttl_ms_; }

    /*──── SEQ do central recebido ────*/
    void note_rx_seq(uint32_t s) {
        if (s != 0)
            last_rx_seq_ = s;
    }
    uint32_t last_rx_seq() const   { return last_rx_seq_;  }

    void set_remote_window(uint16_t w) { window_remote_ = w; }

    void consume_local_window(size_t n);
    void release_local_window(size_t n);

    /*──── enqueue & fragmentação ────*/
    void queue_data(const std::vector<uint8_t>& payload, bool is_revive = false);

    /*──── trata ACK recebido ────*/
    void handle_ack(uint32_t acknum, uint16_t win_remote, uint32_t new_sttl);

    /*──── agendamento de envio ────*/
    std::vector<Outbound*> ready_to_send(int rto_ms);
    void mark_sent(Outbound* o) { o->last_sent = std::chrono::steady_clock::now(); }
    bool empty() const          { return txq_.empty(); }

private:
    uint16_t window_remote_left() const;

    UUID      sid_;
    uint32_t  sttl_ms_;
    uint32_t  next_seq_, last_ack_rcvd_;
    uint16_t  local_window_, window_remote_;
    uint8_t   next_fid_;
    uint32_t  last_rx_seq_;
    std::chrono::steady_clock::time_point start_;
    std::deque<Outbound> txq_;
};

/*──────────────── IMPLEMENTAÇÃO ───────────────*/

inline void Session::consume_local_window(size_t n) {
    local_window_ = (n > local_window_) ? 0 : static_cast<uint16_t>(local_window_ - n);
}
inline void Session::release_local_window(size_t n) {
    constexpr uint32_t LIM = 65535;
    local_window_ = static_cast<uint16_t>(std::min<uint32_t>(LIM, local_window_ + n));
}

inline uint16_t Session::window_remote_left() const {
    size_t in_flight = 0;
    for (const auto& o : txq_)
        if (o.last_sent.time_since_epoch().count() != 0)
            in_flight += o.pkt.data.size();
    return window_remote_ > in_flight ? window_remote_ - in_flight : 0;
}

inline void Session::queue_data(const std::vector<uint8_t>& payload, bool is_revive) {
    constexpr size_t MAX_PAY = 1440;
    size_t  off = 0;
    uint8_t fo = 0;

    if (payload.empty() && is_revive) {
        Packet p;
        p.sid    = sid_;
        p.sttl   = sttl_ms_;
        p.flags  = FLAG_REVIVE | FLAG_ACK;
        p.seqnum = next_seq_++;
        p.acknum = last_rx_seq_;
        p.window = local_window_left();
        txq_.push_back({p});
        return;
    }

    while (off < payload.size()) {
        size_t avail = window_remote_left();
        if (avail == 0 && !txq_.empty()) return;

        size_t here  = std::min({avail == 0 ? MAX_PAY : avail, MAX_PAY, payload.size() - off});

        Packet p;
        p.sid    = sid_;
        p.sttl   = sttl_ms_;
        p.flags  = FLAG_ACK;

        if (is_revive && off == 0) {
            p.flags |= FLAG_REVIVE;
        }

        p.seqnum = next_seq_++;
        p.acknum = last_rx_seq_;
        p.window = local_window_left();

        uint8_t fid = (payload.size() > MAX_PAY) ? next_fid_ : 0;
        p.fid    = fid;
        p.fo     = static_cast<uint8_t>(fo++);
        if (off + here < payload.size()) {
            p.flags |= FLAG_MOREBITS;
        }

        p.data.assign(payload.begin() + off, payload.begin() + off + here);
        txq_.push_back({p});
        off += here;
    }

    if (payload.size() > MAX_PAY) {
        next_fid_++;
    }
}


inline void Session::handle_ack(uint32_t acknum, uint16_t win_remote, uint32_t new_sttl) {
    last_ack_rcvd_ = acknum;
    window_remote_ = win_remote;
    sttl_ms_       = new_sttl;
    while (!txq_.empty() && txq_.front().pkt.seqnum <= acknum)
        txq_.pop_front();
}

// ▼▼▼ FUNÇÃO COM A CORREÇÃO FINAL ▼▼▼
inline std::vector<Outbound*> Session::ready_to_send(int rto_ms) {
    std::vector<Outbound*> v;
    size_t bytes_left = window_remote_left();
    auto   now        = std::chrono::steady_clock::now();

    for (auto& ob : txq_) {
        bool never_sent = ob.first_sent.time_since_epoch().count() == 0;
        bool timed_out  = !never_sent && (now - ob.last_sent) > std::chrono::milliseconds(rto_ms);

        if (!never_sent && !timed_out) {
            continue; // Já foi enviado e ainda não deu timeout
        }

        bool is_revive_packet = (ob.pkt.flags & FLAG_REVIVE);

        // Um pacote pode ser enviado se:
        // 1. For o pacote de REVIVE (tem passe livre para abrir a conexão).
        // 2. Ou se ele couber na janela remota.
        if (is_revive_packet || ob.pkt.data.size() <= bytes_left) {
            v.push_back(&ob);
            // Desconta da janela apenas se for um pacote de dados comum.
            if (!is_revive_packet) {
                bytes_left -= ob.pkt.data.size();
            }
        } else {
            // Se um pacote de dados não couber na janela, paramos por aqui.
            break;
        }
    }
    return v;
}

} // namespace slow