#!/bin/Rscript

require(graphics)

args=commandArgs(trailingOnly=TRUE)
if (length(args)<1) {
	stop("too few arguments")
	exit
}

fndata=args[1]
tdata=read.table(file=fndata)

ssusi<- matrix(NA, nrow=nrow(tdata), ncol=2)
dsusi<- matrix(NA, nrow=nrow(tdata), ncol=2)
dsusiins<- matrix(NA, nrow=nrow(tdata), ncol=2)
drisk<- matrix(NA, nrow=nrow(tdata), ncol=4)

f.per <- function (x,y) {
	if (y<1e-10) return (0)
	return (x/y*100)
}

r=1
inv=1
for(i in seq(1,nrow(tdata),1)) {
	if (sum(tdata[i,3:4])<1e-10) {
		inv<-inv+1
		next
	}

	curssusi<- c(f.per(tdata[i,1],tdata[i,5]), f.per(tdata[i,2],tdata[i,5]))
	ssusi[r,] <- curssusi

	curdsusi<- c(f.per(tdata[i,3],tdata[i,6]), f.per(tdata[i,4],tdata[i,6]))
	dsusi[r,] <- curdsusi

	curdsusiins<- c(f.per(tdata[i,8],tdata[i,7]), f.per(tdata[i,9],tdata[i,7]))
	dsusiins[r,] <- curdsusiins

	curdrisk<- c(f.per(tdata[i,10],tdata[i,3]), f.per(tdata[i,11],tdata[i,4]), f.per(tdata[i,12],tdata[i,8]), f.per(tdata[i,13],tdata[i,9]))
	drisk[r,] <- curdrisk

	r <- r+1
}

print(paste(inv," invalid data points ignored."))

colors2<-c("red","green") #,"black","yellow","darkorange","darkorchid","gold4","darkgrey")
colors4<-c("red","green","blue","darkorange") #,"black","yellow","darkorange","darkorchid","gold4","darkgrey")

pdf("./srcsink-s.pdf")
boxplot(ssusi, names=c("source","sink"),col=colors2,ylab="percentage")
meanssusi <- (colMeans(ssusi, na.rm=TRUE))
points(meanssusi, col="gold", pch=18, cex=1.5)

pdf("./srcsink-d.pdf")
boxplot(dsusi, names=c("source","sink"),col=colors2,ylab="percentage")
meandsusi <- (colMeans(dsusi, na.rm=TRUE))
points(meandsusi, col="gold", pch=18, cex=1.5)

pdf("./srcsink-dins.pdf")
boxplot(dsusiins, names=c("source","sink"),col=colors2,ylab="percentage")
meandsusiins <- (colMeans(dsusiins, na.rm=TRUE))
points(meandsusiins, col="gold", pch=18, cex=1.5)

pdf("./srcsink-risk.pdf")
boxplot(drisk, names=c("esc-src-uniq","rch-sink-uniq","esc-src-ins","rch-sink-ins"),col=colors4,ylab="percentage")
meandrisk <- (colMeans(drisk, na.rm=TRUE))
points(meandrisk, col="gold", pch=18, cex=1.5)

#dev.off


