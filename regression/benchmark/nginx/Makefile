MKFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
CUR_DIR := $(patsubst %/,%,$(dir $(MKFILE_PATH)))
INITRAMFS ?= $(CUR_DIR)/../../build/initramfs
NGINX_DIR := ${INITRAMFS}/usr/local/nginx
WRK_DIR := ${INITRAMFS}/usr/local/wrk
HOST_NGINX_DIR := /usr/local/nginx

.PHONY: all wrk

all: wrk
	@mkdir -p ${NGINX_DIR}/sbin ${NGINX_DIR}/conf ${NGINX_DIR}/logs ${NGINX_DIR}/html
	@# Copy nginx binary and config file
	@cp -a ${HOST_NGINX_DIR}/sbin/nginx ${NGINX_DIR}/sbin
	@cp -a ${HOST_NGINX_DIR}/conf/nginx.conf ${NGINX_DIR}/conf
	@cp -a ${HOST_NGINX_DIR}/conf/mime.types ${NGINX_DIR}/conf
	@cp -a ${HOST_NGINX_DIR}/html/index.html ${NGINX_DIR}/html
	@cp -a ${HOST_NGINX_DIR}/html/50x.html ${NGINX_DIR}/html

	@# Copy libraries 
	@mkdir -p ${INITRAMFS}/lib/x86_64-linux-gnu
	@cp -L /lib/x86_64-linux-gnu/libcrypt.so.1 ${INITRAMFS}/lib/x86_64-linux-gnu

	@# Copy etc files
	@mkdir -p ${INITRAMFS}/etc
	@cp -a group ${INITRAMFS}/etc
	@cp -a passwd ${INITRAMFS}/etc
	@cp -a /etc/nsswitch.conf ${INITRAMFS}/etc
	
	@# Copy nologin
	@mkdir -p ${INITRAMFS}/usr/sbin
	@cp -a /usr/sbin/nologin ${INITRAMFS}/usr/sbin

wrk: 
	@# Copy wrk
	@mkdir -p ${WRK_DIR}
	@cp -a /root/wrk/wrk ${WRK_DIR}
	@# Copy libraries
	@mkdir -p ${INITRAMFS}/lib/x86_64-linux-gnu
	@cp -L /lib/x86_64-linux-gnu/libm.so.6 ${INITRAMFS}/lib/x86_64-linux-gnu
