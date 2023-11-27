#! /bin/sh

#########################################################################
#MTK
export PATH=$PATH:/opt/buildroot-gcc463/usr/bin
ARCH=mipsel-linux
COMPILER=/opt/buildroot-gcc463/usr/bin/mipsel-linux-
USE_URANDOM=1

#########################################################################
#export PATH=$PATH:/opt/buildroot-gcc463/usr/bin
#ARCH=arm-linux
#COMPILER=arm-fullhan-linux-uclibcgnueabi-
#USE_URANDOM=1
###########################################################################




###########################################################################
#
LIB_DIR=$(pwd)/lib
rm -rf bin
mkdir lib bin

#libnl-3.2.25
echo "Build libnl-3.2.25 ..."
if [ ! -d  libnl-3.2.25 ]; then
	tar xfz ../libnl-3.2.25.tar.gz
	cd libnl-3.2.25
	./configure CFLAGS="-ffunction-sections -fdata-sections" --host=${ARCH} --prefix=${LIB_DIR} --enable-shared --enable-static CC=${COMPILER}gcc
	cd ..
fi
cd libnl-3.2.25;make;make install;cd -

#openssl-1.0.2l
echo "Build openssl-1.0.2l ..."
if [ ! -d  openssl-1.0.2l ]; then
	tar xfz ../openssl-1.0.2l.tar.gz
	cd openssl-1.0.2l
	./Configure linux-generic32 no-asm shared no-async --prefix=${LIB_DIR} --cross-compile-prefix=${COMPILER}
	cd ..
fi
cd openssl-1.0.2l;make;make install_sw;cd -

#
echo "Build hostapd-2.9 ..."
if [ ! -d  hostapd-2.9 ]; then
	tar xfz hostapd-2.9.tar.gz
	cp hostapd.config hostapd-2.9/hostapd/.config
	[ "X$USE_URANDOM" == "X1" ] && sed -i "s/\/dev\/random/\/dev\/urandom/g" hostapd-2.9/src/crypto/random.c
fi
cd hostapd-2.9/hostapd;make CC=${COMPILER}gcc AR=${COMPILER}ar STRIP=${COMPILER}strip; cd -
cp -fv hostapd-2.9/hostapd/hostapd          bin/hostapd
cp -fv hostapd-2.9/hostapd/hostapd_cli      bin/hostapd_cli
${COMPILER}strip bin/hostapd
${COMPILER}strip bin/hostapd_cli

#
echo "Build wpa_supplicant-2.9 ..."
if [ ! -d  wpa_supplicant-2.9 ]; then
	tar xfz wpa_supplicant-2.9.tar.gz
	cp wpa_supplicant.config wpa_supplicant-2.9/wpa_supplicant/.config
	[ "X$USE_URANDOM" == "X1" ] && sed -i "s/\/dev\/random/\/dev\/urandom/g" wpa_supplicant-2.9/src/crypto/random.c
fi
cd wpa_supplicant-2.9/wpa_supplicant;make CC=${COMPILER}gcc AR=${COMPILER}ar STRIP=${COMPILER}strip; cd -
cp -fv wpa_supplicant-2.9/wpa_supplicant/wpa_supplicant bin/wpa_supplicant
cp -fv wpa_supplicant-2.9/wpa_supplicant/wpa_passphrase bin/wpa_passphrase
cp -fv wpa_supplicant-2.9/wpa_supplicant/wpa_cli        bin/wpa_cli
${COMPILER}strip bin/wpa_cli
${COMPILER}strip bin/wpa_passphrase
${COMPILER}strip bin/wpa_supplicant

#
echo "Build iw 5.0 ..."
if [ ! -d  iw-5.0 ]; then
	tar xfz ../iw-5.0.tar.gz
	cp Makefile.iw iw-5.0/Makefile
fi
cd iw-5.0;make CC=${COMPILER}gcc;cd -
cp -fv iw-5.0/iw  bin/iw

echo "Build Test_App ..."
cd ../test_app;make CC=${COMPILER}gcc AR=${COMPILER}ar STRIP=${COMPILER}strip;cd -
mv -fv ../test_app/bin/*  bin/


#
#cp -vf bin/* ../RT288x_SDK/source/romfs/sbin/
