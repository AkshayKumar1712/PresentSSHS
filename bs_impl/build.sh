rm -r build
mkdir build
cd build
export PICO_SDK_PATH=/home/akshaykotagiri/pico/pico-sdk
cmake ..
make -j4
explorer.exe .