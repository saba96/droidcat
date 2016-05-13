pushd .
cd /home/hcai/testbed/results/ICCReport/overall
cp *.R *.txt /home/hcai/gitrepo/DroidFax/results/ICCReport/overall/
cp *.R /home/hcai/gitrepo/DroidFax/scripts/
cp *.pdf /home/hcai/gitrepo/writings/AndroidstudyPaper/graphics/icc/
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
