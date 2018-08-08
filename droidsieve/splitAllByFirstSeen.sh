
#tool=splitAfonsoByFirstSeen.py
tool=splitDroidsieveByFirstSeen_fast.py

python $tool ~/Downloads/VirusTotalApi/firstseen-zoo2010.txt zoo 2010
python $tool ~/Downloads/VirusTotalApi/firstseen-zoo2011.txt zoo 2011
python $tool ~/Downloads/VirusTotalApi/firstseen-zoo2012.txt zoo 2012
python $tool ~/Downloads/VirusTotalApi/firstseen-zoo2017.txt zoo 2017

python $tool ~/Downloads/VirusTotalApi/firstseen-zoobenign2010.txt zoobenign 2010 true
python $tool ~/Downloads/VirusTotalApi/firstseen-zoobenign2011.txt zoobenign 2011 true
python $tool ~/Downloads/VirusTotalApi/firstseen-zoobenign2012.txt zoobenign 2012 true
python $tool ~/Downloads/VirusTotalApi/firstseen-zoobenign2013.txt zoobenign 2013 true
python $tool ~/Downloads/VirusTotalApi/firstseen-zoobenign2014.txt zoobenign 2014 true
python $tool ~/Downloads/VirusTotalApi/firstseen-zoobenign2015.txt zoobenign 2015 true
python $tool ~/Downloads/VirusTotalApi/firstseen-zoobenign2016.txt zoobenign 2016 true

python $tool ~/Downloads/VirusTotalApi/firstseen-vs2013.txt vs 2013
python $tool ~/Downloads/VirusTotalApi/firstseen-vs2014.txt vs 2014
python $tool ~/Downloads/VirusTotalApi/firstseen-vs2015.txt vs 2015
python $tool ~/Downloads/VirusTotalApi/firstseen-vs2016.txt vs 2016

python $tool ~/Downloads/VirusTotalApi/firstseen-benign2017.txt benign 2017 true

