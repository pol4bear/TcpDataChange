#pragma once

#include <unordered_map>
#include <cstring>
#include <string>
#include "NetfilterManager.h"
#include "TcpFlowManager.h"
#include "pol4b_ip.h"
#include "pol4b_tcp.h"

namespace pol4b {
class TcpDataChanger
{
public:
#define ACCEPT_AND_THROW(x) nfq_set_verdict(queue_handle, ntohl(packet_header->packet_id), NF_ACCEPT, 0, nullptr); throw x

    using WordMap = std::unordered_map<std::string, std::string>;
    static WordMap word_map;

    TcpDataChanger(NetfilterManager::OnError cb_on_error_in = nullptr);

private:
    static TcpFlowManager flow_manager;

    static int data_change(nfq_q_handle *queue_handle, nfgenmsg *message, nfq_data *netfilter_data, void *data);

public:

    bool is_started();

    void start(uint16_t queue = NetfilterManager::DEFAULT_QUEUE_NUM);
    void start(uint16_t queue, uint16_t address_family);
    void stop();

private:
    NetfilterManager netfilter_manager;

private:
    NetfilterManager::OnError cb_on_error;

    void on_error(int error_code);

};
}
