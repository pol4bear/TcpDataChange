#include "NetfilterManager.h"

namespace pol4b {
NetfilterManager::NetfilterManager(OnError cb_on_error_in)
    : handle(nullptr), queue_handle(nullptr), fd(0),
      flag_started(false), cb_on_error(cb_on_error_in){}

int NetfilterManager::default_callback(nfq_q_handle *queue_handle, nfgenmsg *message,
                                       nfq_data *netfilter_data, void *data) {
    nfqnl_msg_packet_hdr *packet_header = nfq_get_msg_packet_hdr(netfilter_data);
    if (packet_header == nullptr) throw Error::NFQ_GET_PACKET_HEADER;
    int id = ntohl(packet_header->packet_id);
    return nfq_set_verdict(queue_handle, id, NF_ACCEPT, 0, nullptr);
}

void *NetfilterManager::loop(void *obj_pointer) {
    NetfilterManager *handle = (NetfilterManager*)obj_pointer;

    try {
        while(handle->flag_started) {
            handle->received_size = recv(handle->fd, handle->buf, sizeof(buf), 0);

            if(handle->received_size >= 0) {
                nfq_handle_packet(handle->handle, handle->buf, handle->received_size);
                continue;
            }
            else if(errno == ENOBUFS) {
                handle->on_error(Error::NFQ_LOSING_PACKETS);
                continue;
            }

            handle->on_error(Error::NFQ_RECV);
            break;
        }
    }
    catch(Error::Code error_code) { handle->on_error(error_code); }

    return nullptr;
}

bool NetfilterManager::is_started() {
    return flag_started;
}

void NetfilterManager::start(uint16_t queue) {
    try {
        start(queue, nullptr, nullptr, DEFAULT_ADDRESS_FAMILY);
    } catch(Error::Code error_code) { throw error_code; }
}

void NetfilterManager::start(nfq_callback *callback, void *data) {
    try {
        start(DEFAULT_QUEUE_NUM, callback, data, DEFAULT_ADDRESS_FAMILY);
    } catch(Error::Code error_code) { throw error_code; }
}

void NetfilterManager::start(uint16_t queue, uint16_t address_family) {
    try {
        start(queue, nullptr, nullptr, address_family);
    } catch(Error::Code error_code) { throw error_code; }
}

void NetfilterManager::start(uint16_t queue, nfq_callback *callback, void *data) {
    try {
        start(queue, callback, data, DEFAULT_ADDRESS_FAMILY);
    } catch(Error::Code error_code) { throw error_code; }
}

void NetfilterManager::start(uint16_t queue, nfq_callback *callback, void *data, uint16_t address_family) {
    if (flag_started)
        throw Error::ALREADY_STARTED;

    try {
        open(queue, callback, data, address_family);
        if (pthread_create(&job, nullptr, loop, this) != 0)
            throw Error::PTHREAD_CREATE;
        if (pthread_detach(job) != 0)
            throw Error::PTHREAD_DETACH;
    } catch(Error::Code error_code) { throw error_code; }

    flag_started = true;
}

void NetfilterManager::stop() {
    flag_started = false;
}

void NetfilterManager::open(uint16_t queue, nfq_callback *callback, void *data, uint16_t address_family) {
    handle = nfq_open();
    if (handle == nullptr)
        throw Error::NFQ_OPEN;
    if (nfq_unbind_pf(handle, address_family) < 0)
        throw Error::NFQ_UNBIND;
    if (nfq_bind_pf(handle, address_family) < 0)
        throw Error::NFQ_BIND;

    if (callback == nullptr)
        queue_handle = nfq_create_queue(handle, queue, &default_callback, data);
    else
        queue_handle = nfq_create_queue(handle, queue, callback, data);

    if (queue_handle == nullptr)
        throw Error::NFQ_CREATE_QUEUE;
    if (nfq_set_mode(queue_handle, NFQNL_COPY_PACKET, 0xFFFF) < 0)
        throw Error::NFQ_SET_MODE;

    fd = nfq_fd(handle);
}

void NetfilterManager::on_error(int error_code) {
    if (cb_on_error != nullptr)
        cb_on_error(error_code);
}
}
