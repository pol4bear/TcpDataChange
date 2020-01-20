#include "TcpFlowManager.h"

namespace pol4b {
IpPortPair::IpPortPair() : ip(0), port(0) {}

IpPortPair::IpPortPair(Ip ip_in, uint16_t port_in) : ip(ip_in), port(port_in) {}

bool IpPortPair::operator<(const IpPortPair &rhs) {
    return ip < rhs.ip && port < rhs.port;
}

TcpFlowManager::TcpFlowManager() {}

bool TcpFlowManager::get_sequence_numbers(tcp_seq &seq, tcp_seq &ack, iphdr *ip_header, tcphdr *tcp_header) {
    bool is_reversed = Ip(ip_header->saddr) < Ip(ip_header->daddr);
    TcpFlowKey flow_key(ip_header, tcp_header);
    TcpFlowValue flow_value;

    if(!get_flow_value(flow_key, flow_value))
        return false;

    if(!is_reversed) {
        seq = flow_value.modulated.first;
        ack = flow_value.real.second;
    }
    else {
        seq =  flow_value.modulated.second;
        ack = flow_value.real.first;
    }

    if (flow_value.close)
        flow_map.erase(flow_key);

    return true;
}

void TcpFlowManager::assign(iphdr *ip_header, tcphdr *tcp_header) {
    uint32_t payload_length = TcpUtil::get_tcp_payload_length(ip_header, tcp_header);
    bool is_reversed = Ip(ip_header->saddr) < Ip(ip_header->daddr);
    TcpFlowKey flow_key(ip_header, tcp_header);
    auto value_iterator = flow_map.find(flow_key);
    TcpFlowValue *flow_value = &value_iterator->second;

    if (value_iterator == flow_map.end() && (!tcp_header->fin && !tcp_header->rst)) {
        flow_value = &flow_map[flow_key];

        if (!is_reversed)
            flow_value->set_data(tcp_header->th_seq, tcp_header->th_ack);
        else
            flow_value->set_data(tcp_header->th_ack, tcp_header->th_seq);
    }
    else if(payload_length == 0) {
        if (tcp_header->syn) {
            if (!is_reversed)
                flow_value->set_data(tcp_header->th_seq, tcp_header->th_ack);
            else
                flow_value->set_data(tcp_header->th_ack, tcp_header->th_seq);
        }
        else if(tcp_header->fin) {
            if(flow_value->close_wait) flow_value->close = true;
            else flow_value->close_wait = true;
        }
        else if(tcp_header->rst) {
            flow_value->close_wait = true;
            flow_value->close = true;
        }
        else if(tcp_header->ack) {
            if (!is_reversed) {
                flow_value->modulated.second++;
                flow_value->real.second++;
            }
            else {
                flow_value->modulated.first++;
                flow_value->real.first++;
            }
        }
    }
}

bool TcpFlowManager::increase(iphdr *ip_header, tcphdr *tcp_header, uint32_t payload_size) {
    bool is_reversed = Ip(ip_header->saddr) < Ip(ip_header->daddr);
    TcpFlowKey flow_key(ip_header, tcp_header);
    if (auto flow_pair = flow_map.find(flow_key); payload_size != 0 && flow_pair != flow_map.end()) {
        TcpFlowValue &flow_value = flow_pair->second;

        if (!is_reversed) {
            flow_value.modulated.second += payload_size - 1;
            flow_value.real.second += payload_size - 1;
        }
        else {
            flow_value.modulated.first += payload_size - 1;
            flow_value.real.first += payload_size - 1;
        }

        return true;
    }

    return false;
}

bool TcpFlowManager::modulate(iphdr *ip_header, tcphdr *tcp_header, uint32_t payload_size) {
    if (tcp_header->fin) return false;


    bool is_reversed = Ip(ip_header->saddr) < Ip(ip_header->daddr);
    TcpFlowKey flow_key(ip_header, tcp_header);
    int original_payload_size = TcpUtil::get_tcp_payload_length(ip_header, tcp_header);

    if (auto flow_pair = flow_map.find(flow_key); flow_pair != flow_map.end()) {
        TcpFlowValue &flow_value = flow_pair->second;

        if (!is_reversed) {
            flow_value.real.first += original_payload_size - (original_payload_size == 0 ? 0 : 1);
            flow_value.modulated.first += payload_size - (payload_size == 0 ? 0 : 1);
        }
        else {
            flow_value.real.second += original_payload_size - (original_payload_size == 0 ? 0 : 1);
            flow_value.modulated.second += payload_size - (payload_size == 0 ? 0 : 1);
        }
        return true;
    }

    return false;
}

bool TcpFlowManager::get_flow_value(TcpFlowKey flow_key, TcpFlowValue &flow_value) {
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

TcpFlowManager::TcpFlowValue::TcpFlowValue() : modulated(TcpSeqPair(0, 0)), real(TcpSeqPair(0, 0)), close_wait(false), close(false) {}

TcpFlowManager::TcpFlowValue::TcpFlowValue(tcp_seq start_seq) : modulated(TcpSeqPair(start_seq, 0)), real(TcpSeqPair(start_seq, 0)), close_wait(false), close(false) {}

TcpFlowManager::TcpFlowValue::TcpFlowValue(tcp_seq start_seq, tcp_seq start_ack) : modulated(TcpSeqPair(start_seq, start_ack)), real(TcpSeqPair(start_seq, start_ack)), close_wait(false), close(false) {}

void TcpFlowManager::TcpFlowValue::set_data(tcp_seq seq, tcp_seq ack) {
    seq = ntohl(seq);
    ack = ntohl(ack);
    real.first = seq;
    modulated.first = seq;
    real.second = ack;
    modulated.second = ack;
}
}
