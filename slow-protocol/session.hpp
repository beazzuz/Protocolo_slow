#pragma once
//
//  session.hpp – lógica de janelas, filas e estatísticas do SLOW

// Este arquivo define a classe Session, que gerencia o estado de uma
// conexão SLOW, incluindo controle de fluxo com janelas deslizantes,
// retransmissão e fragmentação de dados.
/
#include "slow_packet.hpp" // Inclui as definições de Packet e UUID.
#include <algorithm>       // Para std::min.
#include <chrono>          // Para medição de tempo (timeouts, timestamps).
#include <cstdint>         // Para tipos inteiros de largura fixa.
#include <deque>           // Para std::deque, usado na fila de transmissão.

namespace slow {

    // Estrutura que representa um pacote na fila de saída (Outbound Queue).
struct Outbound {
    Packet pkt; // O pacote SLOW a ser enviado.
    std::chrono::steady_clock::time_point first_sent{}; // Timestamp da primeira vez que o pacote foi enviado.
    std::chrono::steady_clock::time_point last_sent{};  // Timestamp da última vez que o pacote foi enviado (para RTO).
};

// Classe Session: Gerencia o estado de uma conexão SLOW.
class Session {
public:
// Construtor: Inicializa a sessão com uma janela local padrão.
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
     // Estabelece ou revive uma sessão com base nos parâmetros de um pacote SETUP.
    void establish(const Packet& setup) {
        sid_          = setup.sid;         // Copia o Session ID.
        sttl_ms_      = setup.sttl;        // Copia o Session Time To Live.
        // O próximo número de sequência local é o `seqnum` do pacote SETUP + 1.
        next_seq_     = setup.seqnum + 1;
        window_remote_= setup.window;      // Define a janela remota.
        // O último ACK recebido é o `acknum` do pacote SETUP.
        last_ack_rcvd_ = setup.acknum;
        // Registra o tempo de início da sessão.
        start_        = std::chrono::steady_clock::now();
    }

    /*──── utilidades ────*/
   // Retorna o próximo número de sequência disponível e o incrementa.
    uint32_t take_seq()              { return next_seq_++; }
    // Retorna o próximo número de sequência disponível sem incrementá-lo.
    uint32_t peek_next_seq()   const { return next_seq_;   }
    // Retorna o último ACK recebido.
    uint32_t last_ack()       const  { return last_ack_rcvd_; }
    // Retorna o espaço restante na janela de recepção local.
    uint16_t local_window_left()const{ return local_window_;  }
    // Retorna o Session ID.
    const UUID& sid()         const  { return sid_; }
    // Retorna o Session Time To Live.
    uint32_t  sttl()          const  { return sttl_ms_; }


    /*──── SEQ do central recebido ────*/
    // Registra o último número de sequência de pacote de dados recebido do peer.
    // Usado para gerar ACKs.
    void note_rx_seq(uint32_t s) {
        if (s != 0)
            last_rx_seq_ = s;
    }
    uint32_t last_rx_seq() const   { return last_rx_seq_;  }

    void set_remote_window(uint16_t w) { window_remote_ = w; }

    void consume_local_window(size_t n);
    void release_local_window(size_t n);

    /*──── enqueue & fragmentação ────*/
    // Adiciona um payload de dados à fila de transmissão, fragmentando-o se necessário.
    // `is_revive` indica se o pacote é parte de uma operação de revive (afeta flags).
    void queue_data(const std::vector<uint8_t>& payload, bool is_revive = false);

    /*──── trata ACK recebido ────*/
     // Lida com o recebimento de um pacote ACK.
    // Atualiza o last_ack_rcvd, a janela remota e o STTL.
    // Remove pacotes da fila de transmissão que foram reconhecidos.
    void handle_ack(uint32_t acknum, uint16_t win_remote, uint32_t new_sttl);

    /*──── agendamento de envio ────*/
    // Retorna um vetor de ponteiros para pacotes na fila que estão prontos para serem enviados/retransmitidos.
    // `rto_ms` é o valor do Retransmission Timeout em milissegundos.
    std::vector<Outbound*> ready_to_send(int rto_ms);
    void mark_sent(Outbound* o) { o->last_sent = std::chrono::steady_clock::now(); }
    bool empty() const          { return txq_.empty(); }

private:
// Calcula o espaço restante na janela de recepção remota.
    // Considera os pacotes que já estão "em voo" (enviados mas ainda não ACKed).
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

// Implementação para enfileirar dados e realizar fragmentação.
inline void Session::queue_data(const std::vector<uint8_t>& payload, bool is_revive) {
    constexpr size_t MAX_PAY = 1440;
    size_t  off = 0;
    uint8_t fo = 0;

    // Caso especial: se o payload for vazio e for um pacote de REVIVE,
    // cria um pacote REVIVE/ACK puro (sem dados).
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

    // Loop para fragmentar e enfileirar o payload.
    while (off < payload.size()) {
        size_t avail = window_remote_left();
        // Se não há espaço disponível e a fila não está vazia (há pacotes em voo),
        // não podemos enviar mais.
        if (avail == 0 && !txq_.empty()) return;

        // Calcula quantos bytes podem ser enviados neste fragmento:
        // Mínimo entre: (se avail=0, MAX_PAY; senão avail), MAX_PAY, e bytes restantes do payload.
        size_t here  = std::min({avail == 0 ? MAX_PAY : avail, MAX_PAY, payload.size() - off});

        Packet p;
        p.sid    = sid_;
        p.sttl   = sttl_ms_;
        p.flags  = FLAG_ACK;

        // Se for um pacote de revive e este for o primeiro fragmento (off == 0),
        // adiciona a flag REVIVE.

        if (is_revive && off == 0) {
            p.flags |= FLAG_REVIVE;
        }

        p.seqnum = next_seq_++;
        p.acknum = last_rx_seq_;
        p.window = local_window_left();

        // Se o payload original foi fragmentado (tamanho > MAX_PAY), usa next_fid_.
        // Caso contrário (payload cabe em um único pacote), fid é 0.
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

// Implementação para lidar com ACKs recebidos.
inline void Session::handle_ack(uint32_t acknum, uint16_t win_remote, uint32_t new_sttl) {
    last_ack_rcvd_ = acknum;
    window_remote_ = win_remote;
    sttl_ms_       = new_sttl;
    while (!txq_.empty() && txq_.front().pkt.seqnum <= acknum)
        txq_.pop_front();
}

// ▼▼▼ FUNÇÃO COM A CORREÇÃO FINAL ▼▼▼
// Implementação para determinar quais pacotes estão prontos para serem enviados ou retransmitidos.
inline std::vector<Outbound*> Session::ready_to_send(int rto_ms) {
    std::vector<Outbound*> v;
    size_t bytes_left = window_remote_left();
    auto   now        = std::chrono::steady_clock::now();

// Itera sobre a fila de transmissão.
    for (auto& ob : txq_) {
        bool never_sent = ob.first_sent.time_since_epoch().count() == 0;
        bool timed_out  = !never_sent && (now - ob.last_sent) > std::chrono::milliseconds(rto_ms);

        if (!never_sent && !timed_out) {
            continue; // Já foi enviado e ainda não deu timeout
        }
// Verifica se é um pacote de REVIVE.
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