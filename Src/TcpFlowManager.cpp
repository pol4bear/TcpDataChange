#include "TcpFlowManager.h"

namespace pol4b {
IpPortPair::IpPortPair() : ip(0), port(0) {}

IpPortPair::IpPortPair(Ip ip_in, uint16_t port_in) : ip(ip_in), port(port_in) {}

bool IpPortPair::operator<(const IpPortPair &rhs) {
    return ip < rhs.ip && port < rhs.port;
}

TcpFlowManager::TcpFlowManager() {}

bool TcpFlowManager::get_sequence_diffs(tcp_seq &seq_diff, tcp_seq &ack_diff, IpPortPair src, IpPortPair dst) {
    bool is_reversed = dst.ip < src.ip;
    TcpFlowKey flow_key = is_reversed ? TcpFlowKey(dst, src) : TcpFlowKey(src, dst);
    TcpFlowValue flow_value;

    if(!get_flow_value(flow_key, flow_value)) return false;

    if(!is_reversed) {
        seq_diff = htonl(flow_value.seq_diff);
        ack_diff = htonl(flow_value.ack_diff);
    }
    else {
        seq_diff = htonl(flow_value.seq_diff);
        ack_diff = htonl(flow_value.ack_diff);
    }

    if (flow_value.close)
        flow_map.erase(flow_key);

    return true;
}

void TcpFlowManager::assign(iphdr *ip_header, tcphdr *tcp_header) {
    uint32_t payload_length = TcpUtil::get_tcp_payload_length(ip_header, tcp_header);
    TcpFlowKey flow_key(ip_header, tcp_header);
    auto value_iterator = flow_map.find(flow_key);
    TcpFlowValue *flow_value = &value_iterator->second;

    if (value_iterator == flow_map.end() && (!tcp_header->fin && !tcp_header->rst)) flow_value = &flow_map[flow_key];
    else if(payload_length == 0) {
        if(tcp_header->fin) {
            if (flow_value->close_wait) flow_value->close = true;
            else flow_value->close_wait = true;
        }
        else if(tcp_header->rst) {
            flow_value->close_wait = true;
            flow_value->close = true;
        }
    }
}

bool TcpFlowManager::apply(IpPortPair src, IpPortPair dst, int size) {
    if (size == 0) return true;
    bool is_reversed = dst.ip < src.ip;
    TcpFlowKey flow_key = is_reversed ? TcpFlowKey(dst, src) : TcpFlowKey(src, dst);
    auto value_iterator = flow_map.find(flow_key);
    if (value_iterator == flow_map.end()) return false;
    if (!is_reversed) value_iterator->second.seq_diff += size;
    else value_iterator->second.ack_diff += size;
    return true;
}

bool TcpFlowManager::get_flow_value(const TcpFlowKey &flow_key, TcpFlowValue &flow_value) {
    if (auto flow_pair = flow_map.find(flow_key); flow_pair != flow_map.end()) {
        flow_value =  flow_pair->second;
        return true;
    }

    return false;
}

TcpFlowManager::TcpFlowKey::TcpFlowKey() : src(IpPortPair()), dst(IpPortPair()) {}

TcpFlowManager::TcpFlowKey::TcpFlowKey(IpPortPair src_in, IpPortPair dst_in) : src(src_in), dst(dst_in) {}

TcpFlowManager::TcpFlowKey::TcpFlowKey(iphdr *ip_header, tcphdr *tcp_header) {
    Ip src_ip(ip_header->saddr), dst_ip(ip_header->daddr);

    if (src_ip < dst_ip) {
        src = IpPortPair(src_ip, ntohs(tcp_header->source));
        dst = IpPortPair(dst_ip, ntohs(tcp_header->dest));
    }
    else {
        src = IpPortPair(dst_ip, ntohs(tcp_header->dest));
        dst = IpPortPair(src_ip, ntohs(tcp_header->source));
    }
}

bool TcpFlowManager::TcpFlowKey::operator<(const TcpFlowKey &rhs) const {
    return memcmp(this, &rhs, sizeof(TcpFlowKey)) < 0;
}

TcpFlowManager::TcpFlowValue::TcpFlowValue() : seq_diff(0), ack_diff(0), close_wait(false), close(false) {}

TcpFlowManager::TcpFlowValue::TcpFlowValue(tcp_seq start_seq) : seq_diff(0), ack_diff(0), close_wait(false), close(false) {}

TcpFlowManager::TcpFlowValue::TcpFlowValue(tcp_seq start_seq, tcp_seq start_ack) : seq_diff(0), ack_diff(0), close_wait(false), close(false) {}
}
