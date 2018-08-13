#!/bin/bash

port=${2:-"5556"}
did="emulator-$port"

echo "killing $pidavd ..."
kill -9 $pidavd
echo "- Killing Emulator $did..."
adb -s $did kill-server

echo "- Deleting Emulator" $1
android delete avd -n $1

echo "- Copying emulator template"
cp -r ~/.android/avd/template/$1.* ~/.android/avd/

echo "- Starting emulator"
emulator -avd $1 -scale .3 -no-boot-anim -port $port -no-window &
#emulator -avd $1 -scale .3 -no-boot-anim -port $port &
#emulator -avd $1 -scale .3 -ports 5237,5555 &

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
