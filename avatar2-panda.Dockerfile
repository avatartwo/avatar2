# Note: PANDA is currently not supported on ubuntu 24.04, which makes this file not relevant.
# see https://github.com/panda-re/panda/pull/1536
# and https://github.com/panda-re/panda/pull/1569
#
FROM ubuntu:24.04 AS base


### Pull official panda image
FROM pandare/panda:latest AS panda


### Assemble the final image
FROM avatar2:1.4.8 AS avatar2-panda

# PANDA run-time dependencies
#RUN apt-get update && \
#    apt-get install -y --no-install-recommends \
#        ca-certificates \
#        wget \
#        && \
#    wget 'https://raw.githubusercontent.com/panda-re/panda/refs/heads/dev/panda/dependencies/ubuntu_24.04_base.txt' && \
#    DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends \
#        $(cat ./ubuntu:24.04_base.txt | grep -o '^[^#]*') \
#        ligjpeg9 \
#        libspice-server1 \
#        libprotobuf-c1 \
#        libprotobuf-dev \
#        && \
#    rm -f ./ubuntu:24.04_base.txt && \
#    apt-get remove -y ca-certificates wget

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    libdwarf1 \
    libjsoncpp-dev \
    libprotobuf-c-dev \
    libvte-2.91-0 \
    libwireshark-dev \
    libwiretap-dev \
    wireshark-dev \
    libxen-dev \
    libz3-dev \
    python3 \
    python3-pip \
    wget \
    libpython3-dev \
    genisoimage \
    libffi-dev \
    python3-protobuf \
    python3-colorama \
    liblzo2-2 \
    acl \
    libc6 \
    libcap-ng0 \
    libcap2 \
    libgbm1 \
    libglib2.0-0 \
    libglib2.0-dev \
    zlib1g-dev \
    libgnutls30 \
    libnettle8 \
    libpixman-1-0 \
    libvirglrenderer1 \
    libcurl3-gnutls \
    libglib2.0-0 \
    libiscsi7 \
    librados2 \
    librbd1 \
    libssh-4 \
    libaio1t64 \
    libasound2t64 \
    libbrlapi-dev \
    libc6 \
    libcacard0 \
    libepoxy0 \
    libfdt1 \
    libgbm1 \
    libgcc-s1 \
    libglib2.0-0 \
    libgnutls30 \
    libibverbs1 \
    libjpeg8 \
    libncursesw6 \
    libnuma1 \
    libpixman-1-0 \
    libpmem1 \
    libpng16-16 \
    librdmacm1 \
    libsasl2-2 \
    libseccomp2 \
    libslirp0 \
    libspice-server1 \
    libstdc++6 \
    libtinfo6 \
    libusb-1.0-0 \
    libusbredirparser1 \
    libvirglrenderer1 \
    zlib1g \
    libarchive-dev \
    libssl-dev \
    pkg-config \
    libglib2.0-dev

## Fix lib names expected by panda
#RUN ln -s /usr/lib/x86_64-linux-gnu/libaio.so.1t64 /usr/lib/x86_64-linux-gnu/libaio.so.1 && \
#    ln -s /usr/lib/x86_64-linux-gnu/libbrlapi.so.0.8 /usr/lib/x86_64-linux-gnu/libbrlapi.so.0.7 && \
#    ln -s /usr/lib/x86_64-linux-gnu/libjpeg.so.9 /usr/lib/x86_64-linux-gnu/libjpeg.so.8 && \
#    ln -s /usr/lib/x86_64-linux-gnu/libnettle.so.8 /usr/lib/x86_64-linux-gnu/libnettle.so.7 && \
#    ln -s /usr/lib/x86_64-linux-gnu/libprotobuf.so /usr/lib/x86_64-linux-gnu/libprotobuf.so.17

COPY --from=panda /usr/local /usr/local
RUN apt-get clean && rm -rf /var/lib/apt/lists/*
