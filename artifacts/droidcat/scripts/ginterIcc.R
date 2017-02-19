#!/bin/Rscript

require(graphics)

args=commandArgs(trailingOnly=TRUE)
if (length(args)<1) {
	stop("too few arguments")
	exit
}

fndata=args[1]
tdata=read.table(file=fndata)

sdoverall<- matrix(NA, nrow=nrow(tdata), ncol=2)
dataextra<- matrix(NA, nrow=nrow(tdata), ncol=3)

ginterICC<- matrix(NA, nrow=nrow(tdata), ncol=4)
datainterICC<- matrix(NA, nrow=nrow(tdata), ncol=4)
extrainterICC<- matrix(NA, nrow=nrow(tdata), ncol=4)
bothinterICC<- matrix(NA, nrow=nrow(tdata), ncol=4)

f.per <- function (x,y) {
	if (y<1e-10) return (0)
	return (x/y*100)
}

r=1
inv=1
for(i in seq(1,nrow(tdata),1)) {
	sinterICC=sum(tdata[i,4:5])
	dinterICC=sum(tdata[i,6:7])
	if (dinterICC<1e-10) {
		inv<-inv+1
		next
	}
	cursd <- c(f.per(sinterICC,tdata[i,1]), f.per(dinterICC,tdata[i,3]))
	sdoverall[r,] <- cursd 

	curdataextra<- c(f.per(tdata[i,8],dinterICC), f.per(tdata[i,9],dinterICC), f.per(tdata[i,10],dinterICC))
	dataextra[r,] <- curdataextra 

	curginterICC<- c(f.per(tdata[i,11]+tdata[i,12],dinterICC), f.per(tdata[i,13]+tdata[i,14],dinterICC), f.per(tdata[i,15]+tdata[i,16],dinterICC), f.per(tdata[i,17]+tdata[i,18],dinterICC))
	ginterICC[r,] <- curginterICC 

	r <- r+1
}

print(paste(inv," invalid data points ignored."))

colors2<-c("red","green")
colors3<-c("red","green","blue") #,"black","yellow","darkorange","darkorchid","gold4","darkgrey")
colors4<-c("red","green","blue","darkorange") #,"black","yellow","darkorange","darkorchid","gold4","darkgrey")

pdf("./ginterICC-sd.pdf")
#boxplot(sdoverall[,2], names=c("static","dynamic")[,2],col=colors2,ylab="percentage")
boxplot(sdoverall[,2], names=c("dynamic"),col=colors2,ylab="percentage")
#axis(2, at=pretty(spmcls), lab=pretty(spmcls) * 100, las=TRUE)
meansd <- (colMeans(sdoverall, na.rm=TRUE))
points(meansd, col="gold", pch=18, cex=1.5)

pdf("./ginterICC-data.pdf")
boxplot(dataextra, names=c("data only","extras only","data & extras"),col=colors3,ylab="percentage")
meandataextra <- (colMeans(dataextra, na.rm=TRUE))
points(meandataextra, col="gold", pch=18, cex=1.5)

pdf("./ginterICC-interICC.pdf")
boxplot(ginterICC, names=c("int_ex","int_im","ext_ex","ex_im"),col=colors4,ylab="percentage")
meanginterICC <- (colMeans(ginterICC, na.rm=TRUE))
points(meanginterICC, col="gold", pch=18, cex=1.5)

#dev.off


