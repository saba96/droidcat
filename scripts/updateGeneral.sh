pushd .
cd /home/hcai/testbed/results/generalReport/overall
cp *.R *.txt /home/hcai/gitrepo/DroidFax/results/generalReport/overall/
cp *.R /home/hcai/gitrepo/DroidFax/scripts/
cp *.pdf /home/hcai/gitrepo/writings/AndroidstudyPaper/graphics/general/
cd /home/hcai/gitrepo/DroidFax/
git pull
git add .
git commit -m "updated scripts and results"
git push
cd /home/hcai/gitrepo/writings/AndroidstudyPaper/
git pull
git add .
git commit -m "updated figures"
git push
popd
