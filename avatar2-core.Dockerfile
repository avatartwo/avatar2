### The base avatar2-core image
FROM ubuntu:24.04 AS base

# System essentials
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3 \
        python3-setuptools \
        python3-pip \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*



### The avatar2-core build image
FROM base AS build-core
WORKDIR /avatartwo/avatar2

# avatar2 build dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        git \
        cmake \
        pkg-config \
        build-essential \
        python3-dev \
        python3-pip \
        libcapstone-dev

# Copy the code
#RUN git clone https://github.com/avatartwo/avatar2 /root/avatar2/
COPY . /avatartwo/avatar2

# Build and install
RUN pip3 install --no-cache-dir --break-system-packages .



### Assemble the final image
FROM base AS avatar2-core

# Runtime dependencies and other tools
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ipython3 \
        libcapstone4 \
        gdb \
        gdbserver \
        gdb-multiarch \
        openocd \
        udev \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy installed Python packages
COPY --from=build-core /usr/local /usr/local
RUN apt-get clean && rm -rf /var/lib/apt/lists/*
