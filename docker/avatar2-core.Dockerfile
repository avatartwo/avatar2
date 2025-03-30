### The base avatar2-core image
FROM ubuntu:24.04 AS base

# Runtime dependencies and other tools
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3 \
        python3-setuptools \
        python3-pip \
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
        libcapstone-dev

# Copy the code
COPY . /avatartwo/avatar2 
# Ensure the project was copied properly
RUN ls -la /avatartwo/avatar2/ && \
    if [ ! -f /avatartwo/avatar2/pyproject.toml ]; then echo "pyproject.toml not found!"; exit 1; fi && \
    echo "Project structure verified"

# Build and install
RUN pip3 install --no-cache-dir --break-system-packages .



### Assemble the final image
FROM base AS avatar2-core

# Copy installed Python packages
COPY --from=build-core /usr/local /usr/local
RUN apt-get clean && rm -rf /var/lib/apt/lists/*
