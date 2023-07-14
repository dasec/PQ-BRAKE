#!/bin/bash

# check if the installation is done for the first time
if [ ! -d "tmp" ]; then
  echo "BRAKE is already installed on this device."
  echo -e "To rebuild the app, use the following commands:\n"
  echo -e "cd build\ncmake..\nmake\n"
  echo "Otherwise, consider recloning the repo."
  exit
fi

# check if openssl is installed
if ! command -v openssl &> /dev/null
then
    echo "openssl could not be found, please install it"
    exit
fi
echo "openssl already installed"

# install thimble lib
cd tmp
git clone https://github.com/atxr/thimble
cd thimble
make
sudo make install
cd ..

# install fjfx lib
git clone https://github.com/jerem/FingerJetFXOSE
cd FingerJetFXOSE/FingerJetFXOSE
./runCMake.sh x64
sudo mkdir /usr/local/include/fjfx/
sudo cp libFJFX/include/FJFX.h libFRFXLL/include/FRFXLL* /usr/local/include/fjfx/
cd build/Linux-x86_64/x64
make
cd ../../../dist/Linux-x86_64/x64/
sudo cp libFRFXLL_static.a /usr/local/lib/libFRFXLL.a
sudo cp libFJFX_static.a /usr/local/lib/libFJFX.a
cd ../../../libFJFX/include/
sudo cp FJFX.h /usr/local/include/fjfx/all.h
cd ../../../../

# install NTL
git clone https://github.com/libntl/ntl
cd ntl/src
./configure
make
# make check
sudo make install
cd ../../

# install modified liboqs C library
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
git clone -b main https://github.com/MatejPoljuha/liboqs-PQ-BRAKE
cd liboqs-PQ-BRAKE
sudo mkdir build && cd build
sudo cmake -GNinja ..
sudo ninja install

# clean installation
cd ../../../
sudo rm -r tmp

# build the app
mkdir build
cd build
cmake ..
make
sudo cp ../tests/logs_template/PQBRAKE_results.csv .
cd ..
