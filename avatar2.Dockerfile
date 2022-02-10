### Stage 0: the base avatar2-core image
FROM ubuntu:20.04 AS base

# avatar2 run-time dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 python3-setuptools libcapstone3 gdb gdbserver gdb-multiarch && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*



### Stage 1: The avatar2-core build image
FROM base AS build-core

# avatar2 build dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends git cmake pkg-config build-essential python3-dev python3-pip libcapstone-dev && \
    pip3 install --upgrade --no-cache-dir pip

RUN git clone https://github.com/avatartwo/avatar2 /root/avatar2/
RUN cd /root/avatar2 && \
    python3 setup.py install



### Stage 2: Build avatar-qemu
FROM base AS build-avatar-qemu
ARG QEMU_TARGETS="arm-softmmu,mips-softmmu"

RUN sed -i '/deb-src .*-security main restricted/s/^#//g' /etc/apt/sources.list
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get build-dep -y qemu && \
    apt-get install -y git ninja-build

RUN git clone https://github.com/avatartwo/avatar-qemu /root/avatar-qemu/
RUN cd /root/avatar-qemu/ && \
    git checkout dev/qemu-6.2
RUN mkdir -p /root/avatar-qemu/build && cd /root/avatar-qemu/build && \
    ../configure \
        --disable-sdl \
        --prefix=/usr/local/ \
        --target-list="${QEMU_TARGETS}" && \
    make -j "$(nproc)"
RUN cd /root/avatar-qemu/build/ && make install



### Stage 3: Pull official panda image
FROM pandare/panda:latest AS panda



### Stage 4: Assemble the final image
FROM base AS avatar2

COPY --from=build-core /usr/local /usr/local

RUN apt-get update && \
    apt-get install -y --no-install-recommends libpulse0

COPY --from=build-avatar-qemu /usr/local /usr/local

# PANDA run-time dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates wget && \
    wget 'https://raw.githubusercontent.com/panda-re/panda/master/panda/dependencies/ubuntu:20.04_base.txt' && \
    DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends $(cat ./ubuntu:20.04_base.txt | grep -o '^[^#]*') && \
    rm -f ./ubuntu:20.04_base.txt && \
    apt-get remove -y ca-certificates wget

COPY --from=panda /usr/local /usr/local
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

