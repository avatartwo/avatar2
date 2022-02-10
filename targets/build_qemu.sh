#!/bin/bash
# Usage ./build_qemu.sh [architectures]
# example:  ./build_qemu.sh arm-softmmu,mips-softmmu
#
source /etc/os-release

TARGET_LIST="arm-softmmu,mips-softmmu"
REPO="deb-src http://archive.ubuntu.com/ubuntu/ $UBUNTU_CODENAME-security main restricted"
APT_SRC="/etc/apt/sources.list"
QEMU_NPROC=${QEMU_NPROC:-$(nproc)}


set -ex

if [[ "$ID" == "ubuntu" ]]
then
    if [ $EUID -ne 0 ]; then
          SUDO=sudo
    fi

    if ! grep -q '^deb-src .*'$UBUNTU_CODENAME'-security main restricted' $APT_SRC;
    then
        echo "[WARNING] This script is about to add '$REPO' to $APT_SRC"
        read -p "Do you want to continue? (Yes/No) " cont
        case $cont in
            Yes|yes|Y|y ) 
                $SUDO bash -c "echo '$REPO' >> $APT_SRC"
                echo "Continuing installation..."
                ;;
            * ) echo "Aborting..."
                exit -1
                ;;
        esac
    fi

    $SUDO apt-get update
    DEBIAN_FRONTEND=noninteractive $SUDO apt-get build-dep -y qemu
    $SUDO apt-get install -y git ninja-build
else
    echo "[Warning] Attempting to run installation on a non-ubuntu system."
    echo "You may have to install dependencies manually"
fi


if [[ $# -ge 1 ]]
then
    TARGET_LIST="$1"
fi
echo "Building for targets: $TARGET_LIST"


cd `dirname "$BASH_SOURCE"`/src/
git submodule update --init avatar-qemu 

cd avatar-qemu
git submodule update --init dtc

mkdir -p build
cd build
../configure \
    --disable-sdl \
    --target-list=$TARGET_LIST

make -j $QEMU_NPROC

echo ""
echo "Export the following env variable:"
echo "export AVATAR2_PANDA_EXECUTABLE=$PWD/arm-softmmu/qemu-system-arm"
