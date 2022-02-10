#!/bin/bash
# Usage ./build_panda.sh [architectures]
# example:  ./build_panda.sh arm-softmmu,mips-softmmu
#

TARGET_LIST="arm-softmmu,mips-softmmu,i386-softmmu"
PANDA_NPROC=${PANDA_NPROC:-$(nproc)}


set -ex

source /etc/os-release
if [[ "$ID" != "ubuntu" ]]
then
    echo "[ERROR] This script only supports Ubuntu systems"
    exit -1
fi


if [[ $# -ge 1 ]]
then
    TARGET_LIST="$1"
fi
echo "Building for targets: $TARGET_LIST"
echo ""


# Use the panda install_ubuntu.sh script
cd `dirname "$BASH_SOURCE"`/src/
#git submodule update --init avatar-panda

cd avatar-panda
./panda/scripts/install_ubuntu.sh \
    --disable-sdl \
    --target-list=$TARGET_LIST

echo ""
echo "Export the following env variable:"
echo "export AVATAR2_PANDA_EXECUTABLE=$PWD/arm-softmmu/panda-system-arm"
