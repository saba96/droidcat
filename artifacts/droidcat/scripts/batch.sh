 cp ~/AndroidStudioProjects/HCaiICC23/app/app-release.apk ~/testbed/input/app-release-23.apk 
 iacInstr.sh input/app-release-23.apk 
 signandalign.sh scene.instrumented/app-release-23.apk 
 adb uninstall com.example.hcai.hcaiicc23
 adb install scene.instrumented/app-release-23.apk 
 #adb shell logcat -s "*:E"

