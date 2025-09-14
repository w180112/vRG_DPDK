ARG BUILDER_IMAGE=ubuntu:24.04
ARG RUNTIME_IMAGE=ubuntu:24.04

FROM ${BUILDER_IMAGE} as builder
LABEL maintainer="w180112@gmail.com"
USER root

ADD . /vrg

RUN /vrg/essensials.sh \
    && /vrg/boot.sh

# ---- Runtime Stage ----
ARG RUNTIME_IMAGE=ubuntu:24.04
FROM ${RUNTIME_IMAGE} as runtime
USER root

WORKDIR /vrg

COPY --from=builder /etc/vrg/ /etc/vrg/
COPY --from=builder --chown=root:root --chmod=0755 /usr/local/bin/vrg /usr/local/bin/vrg
COPY --from=builder /usr/local/lib/libutils.so.*.*.* /usr/local/lib/
RUN mkdir -p /var/log/vrg && mkdir -p /var/run/vrg \
    && ln -s /usr/local/lib/libutils.so.* /usr/local/lib/libutils.so \
    && apt update -y && apt install -y libnuma1 libatomic1 libconfig9 \
    libgrpc++1.51t64 && apt clean -y && apt autoclean -y && apt autoremove -y

VOLUME /var/log/vrg
VOLUME /var/run/vrg

ENTRYPOINT ["/usr/local/bin/vrg"]
CMD ["-l", "0-7", "-n", "4"]
