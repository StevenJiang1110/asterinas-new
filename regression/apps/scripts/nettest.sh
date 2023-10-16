#!/bin/sh

set -e

NETTEST_DIR=/regression/network
cd ${NETTEST_DIR}
echo "Start net test......"

./tcp_server 0.0.0.0 8080 &
./tcp_client 127.0.0.1 8080

./tcp_server 127.0.0.1 8081 &
./tcp_client 0.0.0.0 8081

./tcp_server 0.0.0.0 8082 &
./tcp_client 0.0.0.0 8082

./tcp_server 127.0.0.1 8083 &
./tcp_client 127.0.0.1 8083

./udp_server &
./udp_client

./unix_server &
./unix_client

./socketpair
./sockoption

echo "All net test passed"
