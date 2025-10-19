cd ..
mkdir qemu/build
cd qemu/build/
../configure --target-list=arm-softmmu
make -j$(nproc)

cd ../../firmware
make -j$(nproc) all
make -j$(nproc) qemu_start
