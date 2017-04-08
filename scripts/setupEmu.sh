#!/bin/bash

did=${2:-"emulator-5554"}
echo "- Killing All Emulators"
killall -9 emulator64-x86
killall -9 emulator
adb -s $did kill-server

echo "- Deleting Emulator" $1
android delete avd -n $1

echo "- Copying emulator template"
cp -r ~/.android/avd/template/$1.* ~/.android/avd/

echo "- Starting emulator"
#emulator -avd $1 -scale .3 -no-boot-anim &
emulator -avd $1 -scale .3 -ports 5237,5555 &

date1=$(date +"%s")

echo "- Waiting for emulator to boot"
OUT=`adb -s $did shell getprop init.svc.bootanim` 
while [[ ${OUT:0:7}  != 'stopped' ]]; do
  OUT=`adb -s $did shell getprop init.svc.bootanim`
  echo '   Waiting for emulator to fully boot...'
  sleep 5
done

echo "Emulator booted!"

date2=$(date +"%s")
diff=$(($date2-$date1))
echo ".. Emulator boot took $(($diff / 60)) minutes and $(($diff % 60)) seconds." 
