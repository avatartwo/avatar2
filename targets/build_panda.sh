#!/bin/bash
distr=`cat /etc/issue`
ci_distr="Ubuntu 16.04.2 LTS \n \l"

if [[ "$distr" == "$ci_distr" ]]
then
  echo "deb-src http://archive.ubuntu.com/ubuntu/ xenial-security main restricted" >> /etc/apt/sources.list
  apt-get update
  apt-get build-dep -y qemu
fi

cd `dirname "$BASH_SOURCE"`/src/
git submodule update --init avatar-panda

cd avatar-panda
git submodule update --init dtc

mkdir -p ../../build/panda/panda
cd ../../build/panda/panda
../../../src/avatar-panda/configure --disable-sdl --target-list=arm-softmmu
make -j4

