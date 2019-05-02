#!/usr/bin/env bash
# Copyright (C) 2019 Muhammed Ziad <airomyst517@gmail.com>
# This is a free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License

# This script sets an Android virtual device up to
# be used for analysis by Cuckoo.
#
# Outcomes:
#    1- Pushing the prebuilt Python interpreter
#    2- Pushing the cuckoo agent
#    3- Installing helper APKs
#
# Prerequisites:
#    1- The `adb` binary needs to be on your PATH
#    2- An Android virtual device needs to be up and running
#
# How to use:
#    You need to provide this script with your cuckoo working directory
#    in order for it to work properly (make sure it is initialized)
#    ./init_avd.sh <path_to_cuckoo_working_dir> <optional: device serial>

# Path for the cuckoo working directory
cwd=$(cd $1; pwd)

# Checking the cuckoo working directory path
if [ ! -f "${cwd}/.cwd" ]
then
    echo "ERROR: incorrect path for cuckoo working directory,"\
    "make sure your cwd is both correct and initialized!"
    exit
fi
echo "Checked cuckoo working directory!"

# Checking for adb
ADB=$(which adb)
if [ ! -f $ADB ]
then
    echo "ERROR: adb command was not found! Make sure you have the"\
    "Android SDK installed with your PATH configured properly.."
    exit
fi
echo "Found adb binary!"
echo

if [ ! -z $2 ]
then
    ADB="${ADB} -s ${2}"
fi

device_tmp="/data/local/tmp"

# Determine the device architecture
abi=$($ADB shell getprop ro.product.cpu.abi)

all_archs=("arm64" "arm" "x86_64" "x86")
for i in ${all_archs[@]}
do
    if [[ $abi == *"${i}"* ]]
    then
      arch=$i
      break
    fi
done

# Obtain root privileges
$ADB root > /dev/null

# Download and push our prebuilt Python interpreter
tmp_dir=$(mktemp -d "tmp.XXXX")
echo "Downloading the matching Python interpreter for your device.."
wget -qO- "https://github.com/muhzii/community/raw/master/prebuilt/Python3.7/${arch}-android.tar.gz" | tar xz -C $tmp_dir

echo "Pushing Python to the device"
$ADB push "${tmp_dir}/usr" $device_tmp
echo

# Push the cuckoo agent
echo "Pushing the cuckoo agent"
$ADB push "${cwd}/agent/agent.py" $device_tmp
$ADB push "${cwd}/agent/android-agent.sh" $device_tmp
$ADB shell chmod 06755 "${device_tmp}/android-agent.sh"
echo

# Download & Install the ImportContacts application
echo "Downloading and installing ImportContacts.apk"
wget -qP $tmp_dir "https://github.com/cuckoosandbox/cuckoo/raw/master/stuff/android/apps/ImportContacts.apk"
$ADB install "${tmp_dir}/ImportContacts.apk"
echo

# Remove unneeded stuff!
rm -rf $tmp_dir

echo "Device is now ready!"
