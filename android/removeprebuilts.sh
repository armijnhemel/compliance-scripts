#!/bin/sh

# script to clean up Linux kernel images and other prebuilts from the prebuilt
# directory. This assumes that the host machine is a Linux machine (for
# example: Ubuntu 14.04) on x86 or x86-64. The following components are
# removed with this script:
#
# * Linux kernel images
# * qemu
# * all executables compiled for Darwin-x86, Darwin-x86-64, MIPS, MIPS64, MingW


# set this to your Android directory
ANDROID_DIR=/path/to/android

# Linux kernel
rm -f ${ANDROID_DIR}/prebuilts/qemu-kernel/arm/2.6/kernel-qemu
rm -f ${ANDROID_DIR}/prebuilts/qemu-kernel/arm/2.6/kernel-qemu-armv7
rm -f ${ANDROID_DIR}/prebuilts/qemu-kernel/arm/kernel-qemu
rm -f ${ANDROID_DIR}/prebuilts/qemu-kernel/arm/kernel-qemu-armv7
rm -f ${ANDROID_DIR}/prebuilts/qemu-kernel/arm/2.6/vmlinux-qemu
rm -f ${ANDROID_DIR}/prebuilts/qemu-kernel/arm/2.6/vmlinux-qemu-armv7
rm -f ${ANDROID_DIR}/prebuilts/qemu-kernel/arm64/vmlinux-qemu
rm -f ${ANDROID_DIR}/prebuilts/qemu-kernel/arm/vmlinux-qemu
rm -f ${ANDROID_DIR}/prebuilts/qemu-kernel/arm/vmlinux-qemu-armv7
rm -f ${ANDROID_DIR}/prebuilts/qemu-kernel/mips/2.6/kernel-qemu
rm -f ${ANDROID_DIR}/prebuilts/qemu-kernel/mips/2.6/vmlinux-qemu
rm -f ${ANDROID_DIR}/prebuilts/qemu-kernel/mips64/kernel-qemu
rm -f ${ANDROID_DIR}/prebuilts/qemu-kernel/mips64/vmlinux-qemu
rm -f ${ANDROID_DIR}/prebuilts/qemu-kernel/mips/kernel-qemu
rm -f ${ANDROID_DIR}/prebuilts/qemu-kernel/mips/vmlinux-qemu
rm -f ${ANDROID_DIR}/prebuilts/qemu-kernel/x86/2.6/vmlinux-qemu
rm -f ${ANDROID_DIR}/prebuilts/qemu-kernel/x86_64/vmlinux-qemu
rm -f ${ANDROID_DIR}/prebuilts/qemu-kernel/x86/vmlinux-qemu
rm -f ${ANDROID_DIR}/prebuilts/qemu-kernel/x86/vmlinux-vbox
rm -f ${ANDROID_DIR}/prebuilts/qemu-kernel/arm64/kernel-qemu
rm -f ${ANDROID_DIR}/prebuilts/qemu-kernel/x86/2.6/kernel-qemu
rm -f ${ANDROID_DIR}/prebuilts/qemu-kernel/x86_64/kernel-qemu
rm -f ${ANDROID_DIR}/prebuilts/qemu-kernel/x86/kernel-qemu
rm -f ${ANDROID_DIR}/prebuilts/qemu-kernel/x86/kernel-vbox
rm -f ${ANDROID_DIR}/prebuilts/qemu-kernel/x86/pc-bios/bios.bin

# qemu
rm -rf ${ANDROID_DIR}/prebuilts/android-emulator

# clang
rm -rf ${ANDROID_DIR}/prebuilts/clang/darwin-x86

# gcc
rm -rf ${ANDROID_DIR}/prebuilts/gcc/darwin-x86

# misc
rm -rf ${ANDROID_DIR}/prebuilts/misc/darwin-x86
rm -rf ${ANDROID_DIR}/prebuilts/misc/darwin-x86_64
rm -rf ${ANDROID_DIR}/prebuilts/misc/android-mips
rm -rf ${ANDROID_DIR}/prebuilts/misc/android-mips64
rm -rf ${ANDROID_DIR}/prebuilts/misc/windows

# python
rm -rf ${ANDROID_DIR}/prebuilts/python/darwin-x86

# sdk
rm -rf ${ANDROID_DIR}/prebuilts/sdk/tools/darwin
rm -rf ${ANDROID_DIR}/prebuilts/sdk/tools/windows

# tools
rm -rf ${ANDROID_DIR}/prebuilts/tools/darwin-x86
rm -rf ${ANDROID_DIR}/prebuilts/tools/darwin-x86_64
rm -rf ${ANDROID_DIR}/prebuilts/tools/windows
rm -rf ${ANDROID_DIR}/prebuilts/tools/windows-x86_64
