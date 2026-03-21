#! /usr/bin/env bash

# If using linux like fedora, don´t create 17gb of random data in /tmp, since it is a tmpfs and will fill up the RAM.


# Clean dir
rm -rf /var/tmp/dummy_files

rsecure create-key -o /var/tmp/rsecure.key
mkdir -p /var/tmp/dummy_files

# Generate a bunch of random files to test encryption and decryption
for i in {1..50}; do
    dd if=/dev/urandom of=/var/tmp/dummy_files/file_$i.bin bs=1M count=30 status=none
done

# Generate a few large files to test performance
for i in {1..20}; do
    dd if=/dev/urandom of=/var/tmp/dummy_files/thebigone_$i.bin bs=1M count=800 status=progress
done

echo "Generated 70 random files in /var/tmp/dummy_files for testing."
du -shx /var/tmp/dummy_files