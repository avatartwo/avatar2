#!/usr/bin/env python3.8

import argparse


DESCRIPTION="Script to build avatar2 core and its endpoints using Docker."
USAGE=""" generate_dockerfile.py [options]
Example: 
    ./generate_dockerfile.py \\
            --endpoint_list avatar-qemu panda \\
            --qemu_targets arm-softmmu mips-softmmu
"""



BASE_IMAGE='ubuntu:20.04'

avatar2_runtime_dependencies=[ 'python3', 
                               'python3-setuptools',
                               'libcapstone3',
                               'gdb',
                               'gdbserver',
                               'gdb-multiarch']
avatar2_build_dependencies=[ 'git',
                             'cmake',
                             'pkg-config',
                             'build-essential',
                             'python3-dev',
                             'python3-pip',
                             'libcapstone-dev']


TEMPLATE_CORE_BASE=f"""
# avatar2 run-time dependencies
RUN apt-get update && \\
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {' '.join(avatar2_runtime_dependencies)} && \\
    apt-get clean && \\
    rm -rf /var/lib/apt/lists/*
"""

TEMPLATE_CORE_GIT_BUILD=f"""
# avatar2 build dependencies
RUN apt-get update && \\
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {' '.join(avatar2_build_dependencies)} && \\
    pip3 install --upgrade --no-cache-dir pip

RUN git clone https://github.com/avatartwo/avatar2 /root/avatar2/
RUN cd /root/avatar2 && \\
    python3 setup.py install
"""

TEMPLATE_QEMU_BUILD="""
RUN sed -i '/deb-src .*-security main restricted/s/^#//g' /etc/apt/sources.list
RUN apt-get update && \\
    DEBIAN_FRONTEND=noninteractive apt-get build-dep -y qemu && \\
    apt-get install -y git ninja-build

RUN git clone https://github.com/avatartwo/avatar-qemu /root/avatar-qemu/
RUN cd /root/avatar-qemu/ && \\
    git checkout dev/qemu-6.2
RUN mkdir -p /root/avatar-qemu/build && cd /root/avatar-qemu/build && \\
    ../configure \\
        --disable-sdl \\
        --prefix=/usr/local/ \\
        --target-list="${QEMU_TARGETS}" && \\
    make -j "$(nproc)"
RUN cd /root/avatar-qemu/build/ && make install
"""

TEMPLATE_QEMU_RUNTIME="""
RUN apt-get update && \\
    apt-get install -y --no-install-recommends libpulse0

COPY --from=build-avatar-qemu /usr/local /usr/local
"""

TEMPLATE_PANDA=f"""
# PANDA run-time dependencies
RUN apt-get update && \\
    apt-get install -y --no-install-recommends ca-certificates wget && \\
    wget 'https://raw.githubusercontent.com/panda-re/panda/master/panda/dependencies/{BASE_IMAGE}_base.txt' && \\
    DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends $(cat ./ubuntu:20.04_base.txt | grep -o '^[^#]*') && \\
    rm -f ./{BASE_IMAGE}_base.txt && \\
    apt-get remove -y ca-certificates wget

COPY --from=panda /usr/local /usr/local
"""



def generate(endpoint_list, qemu_targets=['arm-softmmu']):

    print(f'[*] Generate avatar2 Dockerfile with the following endpoints: {endpoint_list}')
    stage = 0

    with open('./Dockerfile', 'w') as f:

        # avatar2 base images

        f.write(f'### Stage {stage}: the base avatar2-core image\n')
        f.write(f'FROM {BASE_IMAGE} AS base\n')
        f.write(TEMPLATE_CORE_BASE)


        # Build avatar2 with the specified endpoints

        stage += 1
        f.write(f'\n\n\n### Stage {stage}: The avatar2-core build image\n')
        f.write(f'FROM base AS build-core\n')
        f.write(TEMPLATE_CORE_GIT_BUILD)

        if endpoint_list is not None:

            if 'avatar-qemu' in endpoint_list:
                stage += 1
                f.write(f'\n\n\n### Stage {stage}: Build avatar-qemu\n')
                f.write(f'FROM base AS build-avatar-qemu\n')
                f.write(f'ARG QEMU_TARGETS="{",".join(qemu_targets)}"\n')
                f.write(TEMPLATE_QEMU_BUILD)

            if 'panda' in endpoint_list:
                stage += 1
                f.write(f'\n\n\n### Stage {stage}: Pull official panda image\n')
                f.write('FROM pandare/panda:latest AS panda\n')
                pass


        # Copy artifacts into the final image

        stage += 1
        f.write(f'\n\n\n### Stage {stage}: Assemble the final image\n')
        f.write(f'FROM base AS avatar2\n\n')

        f.write('COPY --from=build-core /usr/local /usr/local\n')

        if endpoint_list is not None:

            if 'avatar-qemu' in endpoint_list:
                f.write(TEMPLATE_QEMU_RUNTIME)

            if 'panda' in endpoint_list:
                f.write(TEMPLATE_PANDA)

        f.write('RUN apt-get clean && rm -rf /var/lib/apt/lists/*\n\n')


if __name__ == '__main__':


    parser = argparse.ArgumentParser(description=DESCRIPTION, usage=USAGE)

    parser.add_argument('-e', '--endpoint_list', nargs='+', default=None,
            choices=['avatar-qemu', 'panda'],
            help='list of endpoints to build with avatar2')

    parser.add_argument('--qemu_targets', nargs='+', default=['arm-softmmu'],
            choices=['arm-softmmu', 'i386-softmmu', 'mips-softmmu', 
                'mipsel-softmmu', 'x86_64-softmmu'],
            help='the target-list argument used to build qemu')

    args = parser.parse_args()

    generate(args.endpoint_list, args.qemu_targets)

