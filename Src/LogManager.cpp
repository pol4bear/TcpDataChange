#include "LogManager.h"

using namespace std;
using namespace google;

namespace pol4b {
LogManager::LogManager(char *log_entry) {
        InitGoogleLogging(log_entry);
        LogToStderr();
}

LogManager::LogManager(string log_entry) {
    LogManager(log_entry.c_str());
}

void LogManager::on_info(string message) {
    LOG(INFO) << message;
}

void LogManager::on_warnig(string message) {
    LOG(WARNING) << message;
}

void LogManager::on_error(string message) {
    LOG(ERROR) << message;
}

void LogManager::on_fatal(string message) {
    LOG(FATAL) << message;
}
}

