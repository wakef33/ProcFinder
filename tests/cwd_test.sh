#!/bin/bash
cp /bin/sleep /tmp/dirOne
sleep 1
mkdir /tmp/.hiddenDIR
cp /bin/sleep /tmp/.hiddenDIR/dirTwo
sleep 1
cp /bin/sleep /dev/shm/dirThree
sleep 1
chmod 755 /tmp/dirOne
chmod 755 /tmp/.hiddenDIR/dirTwo
chmod 755 /dev/shm/dirThree
cd /tmp
./dirOne 600 &
cd -
cd /tmp/.hiddenDIR
./dirTwo 600 &
cd -
cd /dev/shm
./dirThree 600 &
cd -
sleep 600
rm -f /tmp/dirOne
rm -rf /tmp/.hiddenDIR
rm -f /dev/shm/dirThree
