#! /bin/sh

rm -rf bin; mkdir bin
cd tools/bgn_tool/;./build.sh;cd -
cp -fv tools/bgn_tool/bin/* bin
