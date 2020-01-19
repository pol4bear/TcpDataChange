TEMPLATE = app
CONFIG += console c++17
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lnetfilter_queue -lglog -lpthread

SOURCES += \
    Src/LogManager.cpp \
    Src/NetfilterManager.cpp \
    Src/TcpDataChanger.cpp \
    Src/TcpFlowManager.cpp \
    Src/main.cpp \
    Src/pol4b_ip.cpp \
    Src/pol4b_mac.cpp \
    Src/pol4b_tcp.cpp \
    Src/pol4b_util.cpp \
    Src/stdafx.cpp

HEADERS += \
    Src/LogManager.h \
    Src/NetfilterManager.h \
    Src/TcpDataChanger.h \
    Src/TcpFlowManager.h \
    Src/pol4b_ip.h \
    Src/pol4b_mac.h \
    Src/pol4b_tcp.h \
    Src/pol4b_util.h \
    Src/stdafx.h
