#!/usr/bin/bash

function build_libarchive() {
    tag=$1

    dd=$PWD
    cd /tmp
    git clone https://github.com/libarchive/libarchive.git libarchive-src    
    cd libarchive-src; git checkout $tag
    cd /tmp
    mkdir build-libarchive; cd build-libarchive
    cmake ../libarchive-src
    make -j$(nproc);  make install
    cd $dd

}

function install_deps_centos() {
    
    yum install -y epel-release libxml2-devel libzstd-devel xz-devel bzip2-devel
    yum install -y libacl-devel lz4-devel e2fsprogs-devel libb2-devel lzo-devel openssl-devel
    yum install -y librichacl-devel swig strace cmake
}

function install_deps_ubuntu() {
    
    apt-get install -y libxml2-dev libzstd-dev xz-dev bzip2-dev
    apt-get install -y libacl1-dev liblz4-dev libext2fs-dev libb2-dev lzo-dev libssl-dev
    apt-get install -y swig strace cmake
}

os=$1
tag=$2
install_deps_$os
build_libarchive $tag

