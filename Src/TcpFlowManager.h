#pragma once

#include <map>
#include "pol4b_ip.h"
#include "pol4b_tcp.h"

namespace pol4b {
using TcpSeqPair = std::pair<tcp_seq, tcp_seq>;

class TcpFlowManager {
public:
    class TcpFlowKey;
    class TcpFlowValue;
    using TcpFlowMap = std::map<TcpFlowKey, TcpFlowValue>;

public:
    TcpFlowManager();

    bool get_sequence_diffs(tcp_seq &seq_diff, tcp_seq &ack_diff, IpPortPair src, IpPortPair dst);

    void assign(iphdr *ip_header, tcphdr *tcp_header);
    bool apply(IpPortPair src, IpPortPair dst, int size);

private:
    TcpFlowMap flow_map;

    bool get_flow_value(const TcpFlowKey &flow_key, TcpFlowValue &flow_value);

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

        int seq_diff;
        int ack_diff;
        bool close_wait;
        bool close;
    };
};
}
