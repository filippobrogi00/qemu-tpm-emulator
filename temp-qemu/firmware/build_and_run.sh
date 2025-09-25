cd ..
mkdir qemu/build
cd qemu/build/
../configure --target-list=arm-softmmu
make

cd ../../firmware
make all
make qemu_start
