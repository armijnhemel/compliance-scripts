#!/bin/sh

# script to clean up Linux kernel images from the prebuilt directory

ANDROID_DIR=/path/to/android

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
