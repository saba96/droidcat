#!/bin/bash

echo "- Killing All Emulators"
killall emulator64-x86

echo "- Deleting Emulator" $1
android delete avd -n $1

echo "- Copying emulator template"
cp -r ~/.android/avd/template/$1.* ~/.android/avd/

echo "- Starting emulator"
emulator -avd $1 -scale .3 &

date1=$(date +"%s")

echo "- Waiting for emulator to boot"
OUT=`adb shell getprop init.svc.bootanim` 
while [[ ${OUT:0:7}  != 'stopped' ]]; do
  OUT=`adb shell getprop init.svc.bootanim`
  echo '   Waiting for emulator to fully boot...'
  sleep 5
done

echo "Emulator booted!"

date2=$(date +"%s")
diff=$(($date2-$date1))
echo ".. Emulator boot took $(($diff / 60)) minutes and $(($diff % 60)) seconds." 
