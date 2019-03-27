#!/bin/bash

port=${2:-"5554"}
did="emulator-$port"

echo "- Killing Emulator for avd $did"
#killall -9 emulator64-x86
#killall -9 emulator
#adb -s $did kill-server

pid=`ps axf | grep -v grep | grep "$1 -scale .3 -no-window -port $port" | awk '{print $1}'`
#killall -9 qemu-system-i386
echo "killing pid $pid, the process of emulator at port $port, from setupEmu.sh..."
kill -9 $pid

echo "- Deleting Emulator" $1
android delete avd -n $1

echo "- Copying emulator template"
cp -r ~/.android/avd/template/$1.* ~/.android/avd/

echo "- Starting emulator"
#emulator -avd $1 -scale .3 -no-boot-anim -no-window &
#emulator -avd $1 -scale .3 -no-boot-anim -no-window -port $port &
#emulator -avd $1 -scale .3 -no-window -port $port -wipe-data &
emulator -avd $1 -scale .3 -no-window -port $port -gpu off &
#emulator -avd $1 -scale .3 -ports 5237,5555 &

date1=$(date +"%s")

echo "- Waiting for emulator to boot"
OUT=`adb -s $did shell getprop init.svc.bootanim` 
timeout=0
while [[ ${OUT:0:7}  != 'stopped' ]]; do
  OUT=`adb -s $did shell getprop init.svc.bootanim`
  echo '   Waiting for emulator to fully boot...'
  sleep 5
  ((timeout=timeout+5))
  if [ $timeout -ge 180 ];then
      echo "booting emulator time out; bailing out"
      exit 1
  fi
done

echo "Emulator booted!"

date2=$(date +"%s")
diff=$(($date2-$date1))
echo ".. Emulator boot took $(($diff / 60)) minutes and $(($diff % 60)) seconds." 
exit 0
