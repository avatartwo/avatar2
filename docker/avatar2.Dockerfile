FROM ubuntu:24.04 AS base



### Build avatar-qemu
FROM base AS build-avatar-qemu
ARG QEMU_TARGETS="arm-softmmu,mips-softmmu,i386-softmmu,x86_64-softmmu"
ARG QEMU_BRANCH="dev/qemu-8.2"
WORKDIR /avatartwo/avatar-qemu

RUN sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/ubuntu.sources
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get build-dep -y qemu && \
    apt-get install -y git ninja-build

RUN git clone https://github.com/avatartwo/avatar-qemu /avatartwo/avatar-qemu && \
    git checkout ${QEMU_BRANCH}
RUN ./configure \
        --target-list="${QEMU_TARGETS}" \
        --prefix=/usr/local/ \
        --disable-docs \
        --disable-sdl \           
        --disable-opengl \
        --disable-gtk \
        --disable-numa \
        --disable-vnc \
        --disable-curses \
        --disable-virglrenderer \
        --disable-spice \
        --disable-vhost-net \
        --disable-vhost-user \
        --disable-vhost-kernel \
        --disable-rdma \
        --disable-alsa \
        --disable-coreaudio \
        --disable-jack \
        --disable-pa \
        --disable-pipewire \
        --disable-oss \
        && \
    make -j "$(nproc)" && \
    make install



### Stage 3: Assemble the final image
FROM avatartwo/avatar2-core AS avatar2

# QEMU runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libfdt1 \
        libpixman-1-0 \
        libpng16-16t64 \
        libpmem1 \
        libslirp0 \
        libbpf1 \
        libcacard0 \
        libusbredirparser1t64 \
        libsndio7.0 \
        libbrlapi0.8 \
        liburing2 \
        libfuse3-3 \
        libiscsi7 \
        libaio1t64 \
        libgfapi0 \
        libnfs14 \
        librbd1 \
        librados2 \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build-avatar-qemu /usr/local /usr/local
