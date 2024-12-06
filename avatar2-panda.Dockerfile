FROM ubuntu:24.04 AS base


### Pull official panda image
FROM pandare/panda:latest AS panda


### Assemble the final image
FROM avatar2:1.4.8 AS avatar2-panda

# PANDA run-time dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates wget && \
    wget 'https://raw.githubusercontent.com/panda-re/panda/refs/heads/dev/panda/dependencies/ubuntu_22.04_base.txt' && \
    DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends $(cat ./ubuntu:22.04_base.txt | grep -o '^[^#]*') ligjpeg9 libspice-server1 libprotobuf-c1 libprotobuf-dev && \
    rm -f ./ubuntu:20.04_base.txt && \
    apt-get remove -y ca-certificates wget

## Fix lib names expected by panda
RUN ln -s /usr/lib/x86_64-linux-gnu/libaio.so.1t64 /usr/lib/x86_64-linux-gnu/libaio.so.1 && \
    ln -s /usr/lib/x86_64-linux-gnu/libbrlapi.so.0.8 /usr/lib/x86_64-linux-gnu/libbrlapi.so.0.7 && \
    ln -s /usr/lib/x86_64-linux-gnu/libjpeg.so.9 /usr/lib/x86_64-linux-gnu/libjpeg.so.8 && \
    ln -s /usr/lib/x86_64-linux-gnu/libnettle.so.8 /usr/lib/x86_64-linux-gnu/libnettle.so.7 && \
    ln -s /usr/lib/x86_64-linux-gnu/libprotobuf.so /usr/lib/x86_64-linux-gnu/libprotobuf.so.17

COPY --from=panda /usr/local /usr/local
RUN apt-get clean && rm -rf /var/lib/apt/lists/*
