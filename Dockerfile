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



### Stage 2: Assemble the final image
FROM base AS avatar2

COPY --from=build-core /usr/local /usr/local
RUN apt-get clean && rm -rf /var/lib/apt/lists/*