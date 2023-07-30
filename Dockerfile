ARG BUILDER_IMAGE=ubuntu:22.04
ARG RUNTIME_IMAGE=ubuntu:22.04

FROM ${BUILDER_IMAGE} as builder
LABEL maintainer="w180112@gmail.com"
USER root

ADD . /vrg
RUN apt-get update -y \
    && apt-get install -y libnuma-dev linux-headers-$(uname -r) python3-pip git gcc make libtool-bin pkg-config pciutils iproute2 kmod vim net-tools \
    && pip3 install setuptools meson ninja pyelftools \
    && /vrg/boot.sh \
    && apt-get clean -y; apt-get autoclean -y; apt-get autoremove -y

#FROM ${RUNTIME_IMAGE} as rootfs

#RUN apt-get update -y
