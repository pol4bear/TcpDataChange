#include "pol4b_ip.h"

using namespace std;

namespace pol4b {
pol4b::Ip::Ip() {}

pol4b::Ip::Ip(const Ip &ip) {
    memcpy(addr, ip.addr, size);
}

Ip::Ip(uint32_t addr_in) {
    memcpy(addr, &addr_in, size);
}

Ip::Ip(string addr_in) {
    in_addr ip;
    inet_pton(AF_INET, addr_in.c_str(), &ip);
    memcpy(addr, &ip.s_addr, size);
}

std::string Ip::to_string() const {
    return std::to_string(addr[0]) + "." + \
            std::to_string(int(addr[1])) + "." + \
            std::to_string(int(addr[2])) + "." + \
            std::to_string(int(addr[3]));;
}

Ip &Ip::operator=(const Ip &rhs) {
    memcpy(addr, rhs.addr, size);
    return *this;
}

Ip &Ip::operator=(const uint8_t rhs[]) {
    memcpy(addr, rhs, size);
    return *this;
}

bool Ip::operator==(const Ip &rhs) const
{
    return memcmp(addr, rhs.addr, size) == 0;
}

bool Ip::operator==(const uint32_t &rhs) const {
    return *reinterpret_cast<const uint32_t*>(addr) == rhs;
}

bool Ip::operator==(const string &rhs) const {

    return *this == Ip(rhs);
}

bool Ip::operator<(const Ip &rhs) const {
    return uint32_t(*this->addr) < uint32_t(*rhs.addr);
}

Ip::operator string() const {
    return to_string();
}

uint16_t IpUtil::get_ip_checksum(iphdr *ip_header){
    ip_header->check = 0;
    return NetworkUtil::compute_checksum(0, (uint16_t*)ip_header, ip_header->ihl * 4);
}

iphdr *IpUtil::get_ip_header(ethhdr *ether_header) {
    return (iphdr*)((uint8_t*)ether_header + ETH_HLEN);
}
}
