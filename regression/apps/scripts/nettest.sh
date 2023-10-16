#!/bin/sh

set -e

NETTEST_DIR=/regression/network
cd ${NETTEST_DIR}
echo "Start net test......"
./tcp_server &
./tcp_client
./udp_server &
./udp_client
./unix_server &
./unix_client
./socketpair
./sockoption

echo "All net test passed"
