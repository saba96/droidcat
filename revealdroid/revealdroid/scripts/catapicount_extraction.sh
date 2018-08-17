#!/bin/bash
#$ -cwd
#$ -pe openmp 8-64
#$ -q free*,pub*
#$ -j y
#DEBUG_OPTION=-agentlib:jdwp=transport=dt_socket,address=8000,server=y,suspend=y

#export ANDROID_HOME=$ALT_HOME/android-sdks/platforms

export ANDROID_HOME=$HOME/Android/Sdk/platforms
export RD_HOME=.
module load java/1.8.0.51
DEBUG_OPTION=""

#java $DEBUG_OPTION -Dfile.encoding=UTF-8 -classpath bin:./lib/axml-2.0.jar:./lib/slf4j-api-1.7.5.jar:./lib/slf4j-simple-1.7.6.jar:./lib/weka.jar:./lib/jcommander-1.36-SNAPSHOT.jar:../soot/classes:../jasmin/classes:../jasmin/libs/java_cup.jar:../heros/bin:../heros/guava-14.0.1.jar:../heros/slf4j-api-1.7.5.jar:../heros/junit.jar:../heros/org.hamcrest.core_1.3.0.jar:../soot/libs/polyglot.jar:../soot/libs/AXMLPrinter2.jar:../soot/libs/hamcrest-all-1.3.jar:../soot/libs/junit-4.11.jar:../soot/libs/dexlib2-2.0.3-dev.jar:../soot/libs/util-2.0.3-dev.jar:../soot/libs/asm-debug-all-5.0.3.jar:$HOME/Applications/eclipse-jee-luna/plugins/org.junit_4.11.0.v201303080030/junit.jar:$HOME/Applications/eclipse-jee-luna/plugins/org.hamcrest.core_1.3.0.v201303031735.jar:../soot-infoflow/bin:../soot-infoflow/lib/cos.jar:../soot-infoflow/lib/j2ee.jar:../soot-infoflow-android/bin:../soot-infoflow-android/lib/polyglot.jar:../soot-infoflow-android/lib/AXMLPrinter2.jar:../soot-infoflow-android/lib/axml-2.0.jar:../handleflowdroid/bin:$ALT_HOME/android-sdks/platforms/android-20/android.jar:lib/commons-io-2.4.jar:lib/apk-parser-all.jar:lib/logback-classic-1.1.2.jar:lib/logback-core-1.1.2.jar revealdroid.features.apiusage.ExtractCategorizedApiCount $1

MAINCP=bin:$ANDROID_HOME/android-19/android.jar:../soot-infoflow/bin:../soot-infoflow-android/bin:../handleflowdroid/bin:../heros/bin:../soot/classes:../jasmin/classes
for i in lib/*.jar;
do
    MAINCP=$MAINCP:$i
done
for i in ../jasmin/libs/*.jar;
do
    MAINCP=$MAINCP:$i
done
for i in ../heros/*.jar;
do
    MAINCP=$MAINCP:$i
done
for i in ../soot/libs/*.jar;
do
    MAINCP=$MAINCP:$i
done
for i in ../soot-infoflow/lib/*.jar;
do
    MAINCP=$MAINCP:$i
done
for i in ../soot-infoflow-android/lib/*.jar;
do
    MAINCP=$MAINCP:$i
done

java $DEBUG_OPTION -Dfile.encoding=UTF-8 -classpath $MAINCP revealdroid.features.apiusage.ExtractCategorizedApiCount $1
