#!/bin/bash
cp /bin/sleep /tmp/dirOne
sleep 1
mkdir /tmp/.hiddenDIR
cp /bin/sleep /tmp/.hiddenDIR/dirTwo
sleep 1
chmod 755 /tmp/dirOne
chmod 755 /tmp/.hiddenDIR/dirTwo
/tmp/dirOne 600 &
/tmp/.hiddenDIR/dirTwo 600 &
sleep 1
rm -f /tmp/dirOne
rm -rf /tmp/.hiddenDIR
