#! /usr/bin/env bash

# Clean dir
rm -rf /tmp/dummy_files

rsecure create-key -o /tmp/rsecure.key
mkdir -p /tmp/dummy_files

# Generate a bunch of random files to test encryption and decryption
for i in {1..50}; do
    dd if=/dev/urandom of=/tmp/dummy_files/file_$i.bin bs=1M count=30 status=none
done

# Generate a few large files to test performance
for i in {1..20}; do
    dd if=/dev/urandom of=/tmp/dummy_files/thebigone_$i.bin bs=1M count=800 status=progress
done

echo "Generated 70 random files in /tmp/dummy_files for testing."
du -shx /tmp/dummy_files