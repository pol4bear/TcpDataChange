#!/bin/bash

$QUEUE_NUM

QUEUE_NUM=0
if [ -n "$1" ]
then
	$QUEUE_NUM = $1
fi

sudo iptables -F
sudo iptables -A OUTPUT -j NFQUEUE --queue-num $QUEUE_NUM
sudo iptables -A INPUT -j NFQUEUE --queue-num $QUEUE_NUM

