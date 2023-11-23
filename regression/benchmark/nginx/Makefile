MKFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
CUR_DIR := $(patsubst %/,%,$(dir $(MKFILE_PATH)))
INITRAMFS ?= $(CUR_DIR)/../../build/initramfs
NGINX_DIR := ${INITRAMFS}/usr/local/nginx
HOST_NGINX_DIR := /usr/local/nginx

.PHONY: all

all:
	@mkdir -p ${NGINX_DIR}/sbin ${NGINX_DIR}/conf ${NGINX_DIR}/logs
	@# Copy nginx binary and config file
	@cp -a ${HOST_NGINX_DIR}/sbin/nginx ${NGINX_DIR}/sbin
	@cp -a ${HOST_NGINX_DIR}/conf/nginx.conf ${NGINX_DIR}/conf
	@cp -a ${HOST_NGINX_DIR}/conf/mime.types ${NGINX_DIR}/conf
	# @cp -a ${HOST_NGINX_DIR}/conf/fastcgi.conf ${NGINX_DIR}/conf
	# @cp -a ${HOST_NGINX_DIR}/conf/fastcgi_params ${NGINX_DIR}/conf
	# @cp -a ${HOST_NGINX_DIR}/conf/koi-utf ${NGINX_DIR}/conf
	# @cp -a ${HOST_NGINX_DIR}/conf/koi-win ${NGINX_DIR}/conf
	# @cp -a ${HOST_NGINX_DIR}/conf/scgi_params ${NGINX_DIR}/conf
	# @cp -a ${HOST_NGINX_DIR}/conf/uwsgi_params ${NGINX_DIR}/conf
	# @cp -a ${HOST_NGINX_DIR}/conf/win-utf ${NGINX_DIR}/conf

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