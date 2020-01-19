#pragma once

#include <cstdint>
#include <arpa/inet.h>

namespace pol4b {
class NetworkUtil {
public:
    static uint16_t compute_checksum(uint32_t sum, uint16_t *buf, int size);
};
}
