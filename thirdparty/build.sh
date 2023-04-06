#!/usr/bin/env bash

git submodule update --init --recursive

NTL_VERSION="ntl-11.5.1"

wget https://www.shoup.net/ntl/$NTL_VERSION.tar.gz  \
 && tar xf $NTL_VERSION.tar.gz  \
 && rm $NTL_VERSION.tar.gz  \
 && cd $NTL_VERSION/src  \
 && ./configure SHARED=on NTL_GMP_LIP=on NTL_THREADS=on NTL_THREAD_BOOST=on NTL_EXCEPTIONS=on  \
 && make -j4 \
 && make install DESTDIR=$(pwd)/../../NTL \
 && cd ../.. \
 && rm -r $NTL_VERSION

cd HElib \
  && cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo -DNTL_DIR=./../NTL/usr/local/ -DBUILD_SHARED=on -DENABLE_THREADS=ON -DCMAKE_INSTALL_PREFIX=./install . \
  && make -j4 \
  && make install \
  && cd ..

cd SEAL \
  && rm -rf build \
  && mkdir build \
  && cd build \
  && cmake .. \
  && make -j4 \
  && cd ../..

cd tfhe \
  && rm -rf build \
  && mkdir build \
  && cd build \
  && cmake ../src -DCMAKE_BUILD_TYPE=optim -DENABLE_SPQLIOS_AVX=on -DENABLE_SPQLIOS_FMA=on -DCMAKE_INSTALL_PREFIX=./../installed \
  && make -j4 \
  && make install \
  && cd ../..

cd m4ri \
  && autoreconf --install \
  && rm -rf installed \
  && mkdir installed \
  && ./configure --prefix=`pwd`/installed \
  && make -j4 \
  && make install \
  && cd ..
