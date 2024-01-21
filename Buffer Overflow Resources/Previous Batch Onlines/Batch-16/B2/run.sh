#!/bin/bash

# file_name=$(basename -s .c "$1")
file_name=$(basename -s .c "$1" | tr "[:upper:]" "[:lower:]")

executable="${file_name}"
if [ "$2" == "debug" ]; then
    executable="${executable}_dbg"
    debug_flag="-g"
fi

sudo gcc -m32 ${debug_flag} -o "${executable}" -z execstack -fno-stack-protector "$1"
sudo chown root "${executable}"
sudo chmod 4755 "${executable}"