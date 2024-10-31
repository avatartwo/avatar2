FROM ubuntu:20.04 AS base


### Pull official panda image
FROM pandare/panda:latest AS panda


### Assemble the final image
FROM avatar2 AS avatar2-panda

# PANDA run-time dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates wget && \
    wget 'https://raw.githubusercontent.com/panda-re/panda/refs/heads/dev/panda/dependencies/ubuntu_20.04_base.txt' && \
    DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends $(cat ./ubuntu:20.04_base.txt | grep -o '^[^#]*') && \
    rm -f ./ubuntu:20.04_base.txt && \
    apt-get remove -y ca-certificates wget

COPY --from=panda /usr/local /usr/local

RUN apt-get clean && rm -rf /var/lib/apt/lists/*
