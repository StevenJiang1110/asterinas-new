#!/bin/bash

# Number of samples
nsamples=100
# Sleep time between samples (in seconds)
sleeptime=0.1

# Hostname or IP address of the machine running QEMU with GDB server
remote_host="localhost"
# Port number where QEMU GDB server is listening
remote_port="1234"

sleep 0.1

for x in $(seq 1 $nsamples)
do
	# limit the number (to 15) of backtrace since without limitation it would dump lots of trash results
	# Also introduce tremendous amount of time to process these trash results
	gdb -batch \
		-ex "set pagination 0" \
		-ex "file target/osdk/aster-nix/aster-nix-osdk-bin" \
		-ex "target remote $remote_host:$remote_port" \
		-ex "bt -frame-arguments presence -frame-info short-location" >> gdb_perf.log
	sleep $sleeptime
done
