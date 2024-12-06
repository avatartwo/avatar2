FROM ubuntu:24.04 AS base



### Build avatar-qemu
FROM base AS build-avatar-qemu
ARG QEMU_TARGETS="arm-softmmu,mips-softmmu,i386-softmmu,x86_64-softmmu"

RUN sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/ubuntu.sources
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get build-dep -y qemu && \
    apt-get install -y git ninja-build

RUN git clone https://github.com/avatartwo/avatar-qemu /root/avatar-qemu/
RUN cd /root/avatar-qemu/ && \
    git checkout dev/qemu-9.1
RUN cd /root/avatar-qemu/ && \
    ./configure \
        --target-list="${QEMU_TARGETS}" \
        --prefix=/usr/local/ \
        --disable-sdl \
        --disable-gtk \
        --disable-curses \
        --disable-vnc \
        --disable-spice \
        --disable-pipewire \
        --disable-docs
RUN cd /root/avatar-qemu/ && \
    make -j "$(nproc)"
RUN cd /root/avatar-qemu/build/ && make install



### Stage 3: Assemble the final image
FROM avatar2-core AS avatar2

# QEMU runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libaio1t64 \
        libbpf1 \
        libbrlapi0.8 \
        libcacard0 \
        libaio1t64 \
        libasound2t64 \
        libbpf1 \
        libbrlapi0.8 \
        libcacard0 \
        libepoxy0 \
        libfdt1 \
        libfuse3-3 \
        libgbm1 \
        libgfapi0 \
        libibverbs1 \
        libiscsi7 \
        libjack0 \
        libnfs14 \
        libnuma1 \
        libpixman-1-0 \
        libpmem1 \
        libpng16-16t64 \
        libpulse0 \
        librados2 \
        librbd1 \
        librdmacm1t64 \
        libslirp0 \
        libsndio7.0 \
        liburing2 \
        libusbredirparser1t64 \
        libvirglrenderer1 

COPY --from=build-avatar-qemu /usr/local /usr/local
RUN apt-get clean && rm -rf /var/lib/apt/lists/*
