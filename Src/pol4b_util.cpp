#include "pol4b_util.h"

namespace pol4b {
uint16_t NetworkUtil::compute_checksum(uint32_t sum, uint16_t *buf, int size) {
        while (size > 1) {
            sum += *buf++;
            size -= sizeof(uint16_t);
        }
        if (size)
            sum += *(uint8_t *)buf;

        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >>16);

        return (uint16_t)(~sum);
}
}
