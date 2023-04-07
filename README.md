# PresentSSHS
how to run the code for sshs assignment(Do these after make any changes in the crypto.c file)
- create build folder inside ref/bs folder(mkdir build)
- go to build folder (cd build)
- run cmake ..
- run make -j4
- look for a file ending with .uf2, copy & paste this in the Raspberry folder
- After this Raspberry gets converted to serial port look for its number(X) on the device manager ports on windows 
- then run the python file using  python3 test_against_testvectors.py /dev/ttyS(X) from ref/bs folder
Eg. in the below image serial port is running on COM3 which mean we run following command to run tests,  python3 test_against_testvectors.py /dev/ttyS3
![image](https://user-images.githubusercontent.com/37339918/230641658-0edefa8b-f2db-4e19-938e-d35b2f99a8bb.png)
