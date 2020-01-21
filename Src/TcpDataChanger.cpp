#include "TcpDataChanger.h"
#include <vector>

using namespace std;

namespace pol4b {
TcpDataChanger::WordMap TcpDataChanger::word_map = WordMap();
TcpFlowManager TcpDataChanger::flow_manager;

TcpDataChanger::TcpDataChanger(NetfilterManager::OnError cb_on_error_in) :
    netfilter_manager(NetfilterManager()), cb_on_error(cb_on_error_in)  {}

int TcpDataChanger::data_change(nfq_q_handle *queue_handle, nfgenmsg *message, nfq_data *netfilter_data, void *data) {
    nfqnl_msg_packet_hdr *packet_header = nfq_get_msg_packet_hdr(netfilter_data);
    if (packet_header == nullptr) { ACCEPT_AND_THROW(NetfilterManager::Error::NFQ_GET_PACKET_HEADER); }

    uint8_t *packet = nullptr;
    int packet_length = nfq_get_payload(netfilter_data, &packet);
    if (packet_length < 0) { ACCEPT_AND_THROW(NetfilterManager::Error::NFQ_GET_PAYLOAD); }
    else if (ntohs(packet_header->hw_protocol) != ETHERTYPE_IP) return nfq_set_verdict(queue_handle, ntohl(packet_header->packet_id), NF_ACCEPT, 0, nullptr);

    TcpPacket tcp_packet(packet, packet_length);
    flow_manager.assign(tcp_packet.ip_header, tcp_packet.tcp_header);

    list<uint8_t> payload(tcp_packet.payload, tcp_packet.payload + tcp_packet.payload_length);
    uint32_t left_bytes = tcp_packet.payload_length;
    for (auto payload_pointer = payload.begin(); payload_pointer != payload.end(); payload_pointer++, left_bytes--) {
        for (auto it = word_map.begin(); it != word_map.end(); it++) {
            string key = it->first;
            string value = it->second;

            if (left_bytes >= key.length() && *payload_pointer == key[0] && equal(payload_pointer, next(payload_pointer, key.length()), key.begin(), key.end())) {
                int gap = value.length() - key.length();
                int index = 0;
                int index_max = key.length() < value.length() ? key.length() : value.length();
                for (; index < index_max; index++) { *payload_pointer = value[index]; advance(payload_pointer, 1); }
                if (gap > 0)
                    for (; gap > 0; gap--)  { payload.insert(payload_pointer, value[index++]); advance(payload_pointer, 1); }
                else
                    for (; gap < 0; gap++)  { payload_pointer = payload.erase(payload_pointer); left_bytes--; }
            }
        }
    }

    tcp_seq seq_diff, ack_diff;
    if(flow_manager.get_sequence_diffs(seq_diff, ack_diff, tcp_packet.src, tcp_packet.dst)) {
        tcp_packet.tcp_header->th_seq += seq_diff;
        tcp_packet.tcp_header->th_ack += ack_diff;
    }
   flow_manager.apply(tcp_packet.src, tcp_packet.dst, payload.size() - tcp_packet.payload_length);
   tcp_packet.set_payload(payload);
   return nfq_set_verdict(queue_handle, ntohl(packet_header->packet_id), NF_ACCEPT, tcp_packet.packet_length, tcp_packet.packet);
}

bool TcpDataChanger::is_started() {
    return netfilter_manager.is_started();
}

void TcpDataChanger::start(uint16_t queue) {
    try {
        netfilter_manager.start(queue, data_change, &word_map);
    } catch(NetfilterManager::Error::Code error_code) { on_error(error_code); }
}

void TcpDataChanger::start(uint16_t address_family, uint16_t queue) {
    try {
        netfilter_manager.start(address_family, queue, data_change, &word_map);
    } catch(NetfilterManager::Error::Code error_code) { on_error(error_code); }
}

void TcpDataChanger::stop() {
    netfilter_manager.stop();
}

void TcpDataChanger::on_error(int error_code) {
    if (cb_on_error != nullptr)
        cb_on_error(error_code);
}
}
