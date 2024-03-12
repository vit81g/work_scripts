#!/bin/bash
while read line
do
    ./scpcmd.sh /home/rvision/filematrix/filematrix_standard_rhel8.log $line /tmp password
done<"iuspdm2.hosts"