#include "pol4b_mac.h"

using namespace std;
using namespace pol4b;

Mac::Mac() {}

Mac::Mac(uint8_t addr_in[]) {
    memcpy(addr, addr_in, sizeof(Mac));
}

Mac::Mac(const Mac &mac) {
    memcpy(addr, mac.addr, sizeof(Mac));
}

std::string Mac::to_string() const {
       char str_mac[18];
       sprintf(str_mac, "%02X:%02X:%02X:%02X:%02X:%02X", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
       return std::string(str_mac);
}

Mac &Mac::operator=(const Mac &rhs) {
    memcpy(addr, rhs.addr, sizeof(Mac));
    return *this;
}

Mac &Mac::operator=(const uint8_t rhs[]) {
    memcpy(addr, rhs, sizeof(Mac));
    return *this;
}

bool Mac::operator<(const Mac &rhs) const {
    return memcmp(addr, rhs.addr, sizeof(Mac)) < 0;
}

Mac::operator string() const {
    return to_string();
}
