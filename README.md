# DroidCat
This is a fork of DroidCat project, original source code can be found [here](https://bitbucket.org/haipeng_cai/droidcat). \
DroidCat is a dynamic malware detection and categorization technique using supervised learning algorithms on behavioral characterization of Android apps.

You can find usage information at https://chapering.github.io/droidcat. 

## Usage
Note: This repo is going to be completed. Results are not reproducable yet. 
I tried to make results reproducable.
1) First install [Docker](https://docs.docker.com/install/).
2) Open a terminal and run `./build.sh` to set up the right environment in Docker.
3) Then run `./run.sh`. This will open a bash shell in your docker container.
4) Then go to home directory `cd /home`.
5) Clone this repo: `git clone https://github.com/saba96/droidcat.git`
6) Then `cd ./droidcat`.
7) Now run `scripts/cgInstr.sh <Your APK file>`. You can expect to see instrumented apk file under cg.instrumented folder now. If there is no file, an error may have occured so please check out-dynInstr-cg folder to find possible error in instr-<yourApkFile>.err.

You can find usage information at https://chapering.github.io/droidcat.
