#!/bin/sh

echo "*** Running Apache server ***"
/usr/local/apache2/bin/httpd -f /benchmark/apache/httpd.conf -D FOREGROUND &
sleep 1
echo "run wrk client"
/benchmark/bin/wrk http://127.0.0.1:8080/index.html