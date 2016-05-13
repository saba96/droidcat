#!/bin/bash

did=${2:-"emulator-5556"}
echo "- Killing All Emulators"
adb2 -s $did kill-server
killall -9 emulator2

echo "- Deleting Emulator" $1
android delete avd -n $1

echo "- Copying emulator template"
cp -r ~/.android/avd/template/$1.* ~/.android/avd/

echo "- Starting emulator"
#emulator -avd $1 -scale .3 -no-boot-anim &
emulator2 -avd $1 -scale .3 -ports 5359,5557 &

date1=$(date +"%s")

echo "- Waiting for emulator to boot"
OUT=`adb2 -s $did shell getprop init.svc.bootanim` 
while [[ ${OUT:0:7}  != 'stopped' ]]; do
  OUT=`adb2 -s $did shell getprop init.svc.bootanim`
  echo '   Waiting for emulator to fully boot...'
  sleep 5
done

echo "Emulator booted!"

date2=$(date +"%s")
diff=$(($date2-$date1))
echo ".. Emulator boot took $(($diff / 60)) minutes and $(($diff % 60)) seconds." 
