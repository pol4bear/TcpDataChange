#include "pol4b_tcp.h"

using namespace std;

namespace pol4b {
uint16_t TcpUtil::get_tcp_checksum(iphdr *ip_header, tcphdr *tcp_header, uint32_t packet_length) {
    uint32_t sum = 0;
    uint32_t tcp_length = packet_length - ip_header->ihl * 4;

    tcp_header->check = 0;
    sum += (ip_header->saddr >> 16) & 0xFFFF;
    sum += (ip_header->saddr) & 0xFFFF;
    sum += (ip_header->daddr >> 16) & 0xFFFF;
    sum += (ip_header->daddr) & 0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += htons(tcp_length);

    return NetworkUtil::compute_checksum(sum, (uint16_t *)tcp_header, tcp_length);
}

tcphdr *TcpUtil::get_tcp_header(iphdr *ip_header) {
    return (tcphdr*)((uint8_t*)ip_header + ip_header->ihl * 4);
}

uint8_t *TcpUtil::get_tcp_payload(tcphdr *tcp_header, uint8_t *packet_tail) {
    uint32_t payload_length = tcp_header->doff * 4;
    uint8_t *payload_entry = (uint8_t*)tcp_header + payload_length;

    if (payload_length < sizeof(tcphdr)) return nullptr;
    if (payload_entry > packet_tail) return nullptr;
    return payload_entry;
}

uint32_t TcpUtil::get_tcp_payload_length(iphdr *ip_header, tcphdr *tcp_header) {
    return ntohs(ip_header->tot_len) - (ip_header->ihl + tcp_header->doff) * 4;
}

TcpPacket::TcpPacket() : packet(nullptr), packet_length(0), tail(nullptr),
    ip_header(nullptr), tcp_header(nullptr), payload(nullptr), payload_length(0),
    src(), dst(), flag_parsed(false) {}

TcpPacket::TcpPacket(uint8_t *packet_in, uint32_t packet_length_in) : packet_length(packet_length_in), flag_parsed(false) {
    packet = packet_in;

    parse_tcp_packet();
}

TcpPacket::TcpPacket(const TcpPacket &tcp_packet) : packet_length(tcp_packet.packet_length), flag_parsed(false) {
    packet = (uint8_t*)malloc(packet_length);
    memcpy(packet, tcp_packet.packet, packet_length);

    parse_tcp_packet();
}

bool TcpPacket::is_parsed() { return flag_parsed; }

void TcpPacket::set_payload(const list<uint8_t> &payload_in) {
    int gap = payload_in.size() - payload_length;
    if (gap >= 0) ip_header->tot_len += htons(gap);
    else ip_header->tot_len -= htons(gap);
    packet_length += gap;
    payload_length += gap;
    if (payload_length != payload_in.size()) packet = (uint8_t*)realloc(packet, packet_length);
    copy(payload_in.begin(), payload_in.end(), payload);
    compute_all_checksum();
}

void TcpPacket::compute_all_checksum() {
    compute_ip_checksum();
    compute_tcp_checksum();
}

void TcpPacket::compute_ip_checksum() {
    ip_header->check = IpUtil::get_ip_checksum(ip_header);
}

void TcpPacket::compute_tcp_checksum() {
    tcp_header->check = TcpUtil::get_tcp_checksum(ip_header, tcp_header, packet_length);
}

void TcpPacket::parse_tcp_packet() {
    tail = packet + packet_length - 1;
    ip_header = (iphdr*)packet;

    if (ip_header->protocol != IPPROTO_TCP) return;

    tcp_header = TcpUtil::get_tcp_header(ip_header);
    payload_length = TcpUtil::get_tcp_payload_length(ip_header, tcp_header);
    if(payload_length > 0) payload = TcpUtil::get_tcp_payload(tcp_header, tail);
    else payload = nullptr;
    src = IpPortPair(ip_header->saddr, ntohs(tcp_header->source));
    dst = IpPortPair(ip_header->daddr, ntohs(tcp_header->dest));
    flag_parsed = true;
}
}
