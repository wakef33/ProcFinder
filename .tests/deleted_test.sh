#!/bin/bash
cp /bin/sleep /tmp/deletedOne
sleep 1
cp /bin/sleep /tmp/deletedTwo
sleep 1
chmod 755 /tmp/deletedOne
chmod 755 /tmp/deletedTwo
sleep 1
/tmp/deletedOne 600 &
sleep 1
/tmp/deletedTwo 600 &
rm -f /tmp/deletedOne /tmp/deletedTwo
