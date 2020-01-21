#include <iostream>
#include "LogManager.h"
#include "TcpDataChanger.h"

using namespace std;
using namespace pol4b;

void on_error(int error_code);

int main(int argc, char *argv[]) {
    LogManager lm(argv[0]);
    uint16_t queue_number = NetfilterManager::DEFAULT_QUEUE_NUM;
    switch(argc) {
    case 1: break;
    case 2: queue_number = atoi(argv[1]); break;
    default: LogManager::on_fatal("Usage: " + string(argv[0]) + " [Netfilter Queue Number]");
    }

    TcpDataChanger data_changer(on_error);
    data_changer.word_map["hello"] = "Hello2";
    data_changer.word_map["hacking"] = "Hacking";
    data_changer.word_map["About SK"] = "About KT";
    data_changer.word_map["[SK"] = "[KT";


    try {
        data_changer.start(queue_number);
        LogManager::on_info("TcpDataChanger Started!");
    } catch(int error_code) { on_error(error_code); }

    while(data_changer.is_started());

    return 0;
}

void on_error(int error_code) {
    switch(error_code) {
    case NetfilterManager::Error::ALREADY_STARTED:
        LogManager::on_error("TcpDataChanger already started");
        break;
    case NetfilterManager::Error::NFQ_OPEN:
        LogManager::on_fatal("Cannot open NFQ");
        break;
    case NetfilterManager::Error::NFQ_UNBIND:
        LogManager::on_fatal("Cannot unbind NFQ");
        break;
    case NetfilterManager::Error::NFQ_BIND:
        LogManager::on_fatal("Cannot bind NFQ");
        break;
    case NetfilterManager::Error::NFQ_CREATE_QUEUE:
        LogManager::on_error("Cannot create NFQ queue");
        break;
    case NetfilterManager::Error::NFQ_SET_MODE:
        LogManager::on_error("Cannot set NFQ mode");
        break;
    case NetfilterManager::Error::PTHREAD_CREATE:
        LogManager::on_error("Cannot create pthread");
        break;
    case NetfilterManager::Error::PTHREAD_DETACH:
        LogManager::on_error("Cannot detatch pthread");
        break;
    case NetfilterManager::Error::NFQ_LOSING_PACKETS:
        LogManager::on_error("Losing Packets");
        break;
    case NetfilterManager::Error::NFQ_RECV:
        LogManager::on_error("Cannot receive packet from NFQ");
        break;
    case NetfilterManager::Error::NFQ_GET_PACKET_HEADER:
        LogManager::on_error("Cannot get packet header");
        break;
    case NetfilterManager::Error::NFQ_GET_PAYLOAD:
        LogManager::on_error("Cannot get payload");
        break;
    }
}
