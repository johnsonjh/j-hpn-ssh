#!/usr/bin/env bash
#INTERMAC EXTENSION

#compile intermac
cd ../intermaclib
make clean
make

#back to OpenSSH folder
cd ../openssh-portable-intermac

#clean
make clean

#copy intermaclib
cp ../intermaclib/libintermac.a ./libintermac.a

#compile
make
