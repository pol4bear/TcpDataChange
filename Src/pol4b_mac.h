#pragma once

#include <cstdint>
#include <cstring>
#include <string>

namespace pol4b {
class Mac {
public:
    static const int size = 6;

public:
    Mac();
    Mac(uint8_t addr_in[size]);
    Mac(const Mac &mac);

    uint8_t addr[size];

    std::string to_string() const;

    Mac &operator=(const Mac &rhs);
    Mac &operator=(const uint8_t rhs[size]);
    bool operator<(const Mac &rhs) const;

    operator std::string() const;
};
}
