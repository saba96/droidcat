# DroidCat
This is a fork of DroidCat project, original source code can be found [here](https://bitbucket.org/haipeng_cai/droidcat). \
DroidCat is a dynamic malware detection and categorization technique using supervised learning algorithms on behavioral characterization of Android apps. \

You can find usage information at https://chapering.github.io/droidcat. \

## Usage
Note: This repo is going to be completed. Results are not reproducable yet. \
I tried to make results reproducable. \
1) First install [Docker](https://docs.docker.com/install/).
2) Clone this repo: `git clone https://github.com/saba96/droidcat.git`
3) Go to where you have cloned the repo: `cd <where you cloned the repo>/droidcat`
4) Set up docker for having correct environment. `./build.sh`
5) `./run.sh`
6) Then open a new terminal. Paste this `docker ps` to see what is the container id associating with droidcat. Copy the container id for next step.
7) Copy droidcat to your docker container. `cp /<where you cloned the repo>/droidcat <containerId>:/home`
8) Go back to your docker terminal and follow steps at http://chapering.github.io/droidcat/page_usage.html.