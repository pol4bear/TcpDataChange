#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include "pol4b_util.h"

namespace pol4b {
class Ip {
public:
    static const int size = 4;

public:
    Ip();
    Ip(uint32_t addr_in);
    Ip(std::string addr_in);
    Ip(const Ip &ip);

    uint8_t addr[size];

    std::string to_string() const;

    Ip &operator=(const Ip &rhs);
    Ip &operator=(const uint8_t rhs[size]);
    bool operator==(const Ip &rhs) const;
    bool operator==(const uint32_t &rhs) const;
    bool operator==(const std::string &rhs) const;
    bool operator<(const Ip &rhs) const;

    operator std::string() const;
};

class IpUtil {
public:
    static uint16_t get_ip_checksum(iphdr *ip_header);
    static iphdr *get_ip_header(ethhdr *ether_header);
};
}
