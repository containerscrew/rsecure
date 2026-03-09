#! /usr/bin/env bash

rsecure create-key -o /tmp/rsecure.key
mkdir -p /tmp/dummy_files
for i in {1..50}; do
    dd if=/dev/urandom of=/tmp/dummy_files/file_$i.bin bs=1M count=10 status=none
done
dd if=/dev/urandom of=/tmp/dummy_files/thebigone.bin bs=1M count=800 status=progress