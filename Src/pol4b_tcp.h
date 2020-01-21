#pragma once

#include <algorithm>
#include <list>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "pol4b_ip.h"
#include "pol4b_util.h"

namespace pol4b {
class TcpUtil {
public:
    static uint16_t get_tcp_checksum(iphdr *ip_header, tcphdr *tcp_header, uint32_t packet_length);
    static tcphdr *get_tcp_header(iphdr *ip_header);
    static uint8_t *get_tcp_payload(tcphdr *tcp_header, uint8_t *packet_tail);
    static uint32_t get_tcp_payload_length(iphdr *ip_header, tcphdr *tcp_header);
};

class IpPortPair {
public:
    IpPortPair();
    IpPortPair(Ip ip_in, uint16_t port_in);

    Ip ip;
    uint16_t port;

public:
    bool operator<(const IpPortPair &rhs);
};

class TcpPacket {
public:
    TcpPacket();
    TcpPacket(uint8_t *packet_in, uint32_t packet_length_in);
    TcpPacket(const TcpPacket &tcp_packet);

public:
    uint8_t *packet;
    uint32_t packet_length;
    uint8_t *tail;
    iphdr *ip_header;
    tcphdr *tcp_header;
    uint8_t *payload;
    uint32_t payload_length;
    IpPortPair src;
    IpPortPair dst;

    bool is_parsed();
    void set_payload(const std::list<uint8_t> &payload_in);

    void compute_all_checksum();
    void compute_ip_checksum();
    void compute_tcp_checksum();

private:
    void parse_tcp_packet();

private:
    bool flag_parsed;
};
}
