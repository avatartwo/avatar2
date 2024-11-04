### The base avatar2-core image
FROM ubuntu:24.04 AS base

# avatar2 run-time dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 python3-setuptools ipython3 libcapstone4 gdb gdbserver gdb-multiarch openocd udev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*



### The avatar2-core build image
FROM base AS build-core

# avatar2 build dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends git cmake pkg-config build-essential python3-dev python3-pip libcapstone-dev

#RUN git clone https://github.com/avatartwo/avatar2 /root/avatar2/
COPY . /root/avatar2
RUN cd /root/avatar2 && \
    python3 -m pip install --break-system-packages .



### Assemble the final image
FROM base AS avatar2-core

COPY --from=build-core /usr/local /usr/local
RUN apt-get clean && rm -rf /var/lib/apt/lists/*
