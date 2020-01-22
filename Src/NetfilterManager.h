#pragma once

#include <cerrno>
#include <climits>
#include <cstdint>
#include <functional>
#include <pthread.h>
#include <unordered_map>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
extern "C" {
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>
#include <libnetfilter_queue/pktbuff.h>
}

namespace pol4b {
class NetfilterManager
{
public:
    using OnError = std::function<void(int)>;

    NetfilterManager(OnError cb_on_error_in = nullptr);

    static const uint16_t DEFAULT_ADDRESS_FAMILY = AF_INET;
    static const uint16_t DEFAULT_QUEUE_NUM = 0;

private:
    static int default_callback(nfq_q_handle *queue_handle, nfgenmsg *message, nfq_data *netfilter_data, void *data);
    static void *loop(void *obj_pointer);

public:
    bool is_started();

    void start(uint16_t queue = DEFAULT_QUEUE_NUM);
    void start(nfq_callback *callback, void *data);
    void start(uint16_t queue, nfq_callback *callback, void *data);
    void start(uint16_t queue, uint16_t address_family);
    void start(uint16_t queue, nfq_callback *callback, void *data, uint16_t address_family);
    void stop();

private:
    nfq_handle *handle;
    nfq_q_handle *queue_handle;
    int fd;
    char buf[PATH_MAX];
    int received_size;
    pthread_t job;

    void open(uint16_t queue, nfq_callback *callback, void *data, uint16_t address_family);

private:
    // Flags
    bool flag_started;

    OnError cb_on_error;

    void on_error(int error_code);

public:
    class Error {
    public:
        enum Code {
            ALREADY_STARTED = 0x0,
            NFQ_OPEN,
            NFQ_UNBIND,
            NFQ_BIND,
            NFQ_CREATE_QUEUE,
            NFQ_SET_MODE,
            PTHREAD_CREATE,
            PTHREAD_DETACH,
            NFQ_LOSING_PACKETS,
            NFQ_RECV,
            NFQ_GET_PACKET_HEADER,
            NFQ_GET_PAYLOAD,
            NFQ_PKTB_ALLOC,
            NFQ_SET_TRANSPORT_HEADER,
            NFQ_GET_TCP_HEADER,
            NFQ_GET_TCP_PAYLOAD
        };
    };
};
}


