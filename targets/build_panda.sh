#!/bin/bash
source /etc/os-release

if [[ "$ID" == "ubuntu" ]]
then
  sudo bash -c 'echo "deb-src http://archive.ubuntu.com/ubuntu/ '$UBUNTU_CODENAME'-security main restricted" >> /etc/apt/sources.list'
  sudo apt-get update
  sudo apt-get build-dep -y qemu

  # panda-specific deps below, taken from panda/scripts/install_ubuntu.sh
  sudo apt-get -y install python-pip git protobuf-compiler protobuf-c-compiler \
       libprotobuf-c0-dev libprotoc-dev libelf-dev libc++-dev pkg-config
  sudo apt-get -y install software-properties-common
  sudo add-apt-repository -y ppa:phulin/panda
  sudo apt-get update
  sudo apt-get -y install libcapstone-dev libdwarf-dev python-pycparser
fi

cd `dirname "$BASH_SOURCE"`/src/
git submodule update --init avatar-panda

cd avatar-panda
git submodule update --init dtc

mkdir -p ../../build/panda/panda
cd ../../build/panda/panda
../../../src/avatar-panda/configure --disable-sdl --target-list=arm-softmmu
make -j4

