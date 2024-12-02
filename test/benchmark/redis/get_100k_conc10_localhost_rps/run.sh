#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -e

cp /etc/redis.conf.localhost /etc/redis.conf

echo "Running redis server"
/usr/local/redis/bin/redis-server /etc/redis.conf

echo "Running apache bench connected to 127.0.0.1"
/usr/local/redis/bin/redis-benchmark -h 127.0.0.1 -n 100000 -c 5 -t get