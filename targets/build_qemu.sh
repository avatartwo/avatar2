#!/bin/bash
source /etc/os-release

repo="deb-src http://archive.ubuntu.com/ubuntu/ $UBUNTU_CODENAME-security main restricted"
apt_src="/etc/apt/sources.list"

if [[ "$ID" == "ubuntu" ]]
then
    if ! grep -q '^deb-src .*'$UBUNTU_CODENAME'-security main restricted' $apt_src;
    then
        echo "[WARNING] This script is about to add '$repo' to $apt_src"
        read -p "Do you want to continue? (Yes/No) " cont
        case $cont in
            Yes|yes|Y|y ) 
                sudo bash -c "echo '$repo' >> $apt_src"
                echo "Continuing installation..."
                ;;
            * ) echo "Aborting..."
                exit -1
                ;;
        esac
    fi
    sudo apt-get update
    sudo apt-get build-dep -y qemu
else
    echo "[Warning] Attempting to run installation on a non-ubuntu system."
    echo "You may have to install dependencies manually"
fi

cd `dirname "$BASH_SOURCE"`/src/
git submodule update --init avatar-qemu 

cd avatar-qemu
git submodule update --init dtc

mkdir -p ../../build/qemu/
cd ../../build/qemu
../../src/avatar-qemu/configure --disable-sdl --target-list=arm-softmmu 
make -j4

