#!/bin/bash
source /etc/os-release

repo="deb-src http://archive.ubuntu.com/ubuntu/ $UBUNTU_CODENAME-security main restricted"
apt_src="/etc/apt/sources.list"
PANDA_NPROC=${PANDA_NPROC:-$(nproc)}

set -e

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

    # Use the panda install_ubuntu.sh script
    cd `dirname "$BASH_SOURCE"`/src/
    git submodule update --init avatar-panda
    
    cd ..
    src/avatar-panda/panda/scripts/install_ubuntu.sh --disable-sdl --target-list=arm-softmmu

    mkdir -p build/
    mv src/avatar-panda/build/ build/panda/

else
    echo "[Warning] Attempting to run installation on a non-ubuntu system."
    echo "You may have to install dependencies manually"

    cd `dirname "$BASH_SOURCE"`/src/
    git submodule update --init avatar-panda
    
    cd avatar-panda
    git submodule update --init dtc
    
    mkdir -p ../../build/panda/panda
    cd ../../build/panda/panda
    ../../../src/avatar-panda/configure --disable-sdl --target-list=arm-softmmu
    make -j ${PANDA_NPROC}
fi
