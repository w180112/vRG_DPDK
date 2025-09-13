ARG BUILDER_IMAGE=ubuntu:24.04
ARG RUNTIME_IMAGE=ubuntu:24.04

FROM ${BUILDER_IMAGE} as builder
LABEL maintainer="w180112@gmail.com"
USER root

ADD . /vrg

RUN /vrg/essensials.sh \
    && /vrg/boot.sh

#FROM ${RUNTIME_IMAGE} as rootfs

#RUN apt-get update -y
