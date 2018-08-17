#!/bin/bash
#$ -cwd
#$ -pe openmp 2-8
#$ -q seal,free*,pub*
#$ -j y
#$ -l mem_free=64G
#$ -r y
if [ -z ${ALT_HOME+x} ]; then
    ALT_HOME=$HOME
fi


export ANDROID_HOME=$ALT_HOME/Android/Sdk/platforms
export LD_LIBRARY_PATH=lib/

if [ -z ${1+x} ]; then
    echo no apk provided as input, so exiting
    exit 1
fi

#java -Xmx512G -classpath $ALT_HOME/$RD_WORKSPACE/android-reflection-analysis/bin:$ALT_HOME/$RD_WORKSPACE/seal-utils/bin:$ALT_HOME/$RD_WORKSPACE/seal-utils/lib/logback-core-1.1.2.jar:$ALT_HOME/$RD_WORKSPACE/seal-utils/lib/AXMLPrinter2.jar:$ALT_HOME/$RD_WORKSPACE/seal-utils/lib/guava-18.0.jar:$ALT_HOME/$RD_WORKSPACE/seal-utils/lib/logback-classic-1.1.2.jar:$ALT_HOME/$RD_WORKSPACE/soot/testclasses:$ALT_HOME/$RD_WORKSPACE/soot/classes:$ALT_HOME/$RD_WORKSPACE/jasmin/classes:$ALT_HOME/$RD_WORKSPACE/jasmin/libs/java_cup.jar:$ALT_HOME/$RD_WORKSPACE/heros/target/classes:$ALT_HOME/$RD_WORKSPACE/heros/target/test-classes:$ALT_HOME/$RD_WORKSPACE/heros/slf4j-api-1.7.5.jar:$ALT_HOME/$RD_WORKSPACE/heros/slf4j-simple-1.7.5.jar:$ALT_HOME/$RD_WORKSPACE/heros/junit.jar:$ALT_HOME/$RD_WORKSPACE/heros/org.hamcrest.core_1.3.0.jar:$ALT_HOME/$RD_WORKSPACE/heros/mockito-all-1.9.5.jar:$ALT_HOME/$RD_WORKSPACE/heros/guava-18.0.jar:$ALT_HOME/$RD_WORKSPACE/soot/libs/polyglot.jar:$ALT_HOME/$RD_WORKSPACE/soot/libs/AXMLPrinter2.jar:$ALT_HOME/$RD_WORKSPACE/soot/libs/hamcrest-all-1.3.jar:$ALT_HOME/$RD_WORKSPACE/soot/libs/junit-4.11.jar:$ALT_HOME/$RD_WORKSPACE/soot/libs/asm-debug-all-5.1.jar:$ALT_HOME/$RD_WORKSPACE/soot/libs/cglib-nodep-2.2.2.jar:$ALT_HOME/$RD_WORKSPACE/soot/libs/java_cup.jar:$ALT_HOME/$RD_WORKSPACE/soot/libs/javassist-3.18.2-GA.jar:$ALT_HOME/$RD_WORKSPACE/soot/libs/mockito-all-1.10.8.jar:$ALT_HOME/$RD_WORKSPACE/soot/libs/powermock-mockito-1.6.1-full.jar:$ALT_HOME/$RD_WORKSPACE/soot/libs/jboss-common-core-2.5.0.Final.jar:$ALT_HOME/$RD_WORKSPACE/soot/libs/dexlib2-2.2b4-adb12356.jar:$ALT_HOME/$RD_WORKSPACE/soot/libs/util-2.2b4-adb12356.jar:$ALT_HOME/$RD_WORKSPACE/soot-infoflow-android/bin:$ALT_HOME/$RD_WORKSPACE/soot-infoflow-android/lib/AXMLPrinter2.jar:$ALT_HOME/$RD_WORKSPACE/soot-infoflow-android/lib/commons-io-2.4.jar:$ALT_HOME/$RD_WORKSPACE/soot-infoflow/bin:$ALT_HOME/$RD_WORKSPACE/soot-infoflow/lib/cos.jar:$ALT_HOME/$RD_WORKSPACE/soot-infoflow/lib/j2ee.jar:$ALT_HOME/$RD_WORKSPACE/soot-infoflow/lib/slf4j-api-1.7.5.jar:$ALT_HOME/$RD_WORKSPACE/soot-infoflow-android/lib/axml-2.0.jar:$ALT_HOME/$RD_WORKSPACE/handleflowdroid/bin:$ALT_HOME/$RD_WORKSPACE/android-reflection-analysis/lib/javatuples-1.2.jar:$ALT_HOME/$RD_WORKSPACE/android-reflection-analysis/lib/jgrapht-jdk1.6.jar edu.uci.seal.cases.analyses.ReflectUsageTransformer $1

MAINCP=../android-reflection-analysis/bin:../seal-utils/bin:../soot-infoflow/bin:../soot-infoflow-android/bin:../handleflowdroid/bin:$HEROS_CLASSES_DIR:../soot/classes:../jasmin/classes:../soot/testclasses:../heros/target/classes:../heros/target/test-classes
for i in ../android-reflection-analysis/lib/*.jar;
do
    MAINCP=$MAINCP:$i
done
for i in ../seal-utils/lib/*.jar;
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

java -Xmx240g -classpath $MAINCP edu.uci.seal.cases.analyses.ReflectUsageTransformer $1

