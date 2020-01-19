# Tcp Data Changer
## How To Use
> Don't forget to reset iptables settings after using this program `sudo iptables -F`
1. Setup netfilter using iptables `./set_netfilter_queue.sh`
2. Start Tcp Data Changer `./TcpDataChanger  [Netfilter Queue Number]`

## Supported OS
- Linux

## Dependencies
- [libnetfilter_queue]: For change packet data in-path.
- [libglog]: For logging.

[libnetfilter_queue]: https://netfilter.org/projects/libnetfilter_queue/
[libglog]: https://github.com/google/glog
