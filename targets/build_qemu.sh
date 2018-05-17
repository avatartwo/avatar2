#!/bin/bash
source /etc/os-release

if [[ "$ID" == "ubuntu" ]]
then
  sudo bash -c 'echo "deb-src http://archive.ubuntu.com/ubuntu/ '$UBUNTU_CODENAME'-security main restricted" >> /etc/apt/sources.list'
  sudo apt-get update
  sudo apt-get build-dep -y qemu
fi

cd `dirname "$BASH_SOURCE"`/src/
git submodule update --init avatar-qemu 

cd avatar-qemu
git submodule update --init dtc

mkdir -p ../../build/qemu/
cd ../../build/qemu
../../src/avatar-qemu/configure --disable-sdl --target-list=arm-softmmu
make -j4

