#pragma once

#include <map>
#include "pol4b_ip.h"
#include "pol4b_tcp.h"

namespace pol4b {
using TcpSeqPair = std::pair<tcp_seq, tcp_seq>;

class IpPortPair {
public:
    IpPortPair();
    IpPortPair(Ip ip_in, uint16_t port_in);

    Ip ip;
    uint16_t port;

public:
    bool operator<(const IpPortPair &rhs);
};

class TcpFlowManager {
public:
    class TcpFlowKey;
    class TcpFlowValue;
    using TcpFlowMap = std::map<TcpFlowKey, TcpFlowValue>;

public:
    TcpFlowManager();

    bool get_sequence_numbers(tcp_seq &seq, tcp_seq &ack, iphdr *ip_header, tcphdr *tcp_header);

    void assign(iphdr *ip_header, tcphdr *tcp_header);
    bool increase(iphdr *ip_header, tcphdr *tcp_header, uint32_t payload_size);
    bool modulate(iphdr *ip_header, tcphdr *tcp_header, uint32_t payload_size);

private:
    TcpFlowMap flow_map;

    bool get_flow_value(TcpFlowKey flow_key, TcpFlowValue &flow_value);

public:
    class TcpFlowKey {
    public:
        TcpFlowKey();
        TcpFlowKey(IpPortPair src_in, IpPortPair dst_in);
        TcpFlowKey(iphdr *ip_header, tcphdr *tcp_header);

        IpPortPair src;
        IpPortPair dst;

    public:
        bool operator<(const TcpFlowKey &rhs) const;
    };

    class TcpFlowValue {
    public:
        TcpFlowValue();
        TcpFlowValue(tcp_seq start_seq);
        TcpFlowValue(tcp_seq start_seq, tcp_seq start_ack);

        TcpSeqPair modulated;
        TcpSeqPair real;
        bool handshake;
        bool close_wait;
        bool close;
        bool erase;
    };
};
}
