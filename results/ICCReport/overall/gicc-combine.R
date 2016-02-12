#!/bin/Rscript

require(graphics)

args=commandArgs(trailingOnly=TRUE)
if (length(args)<2) {
	stop("too few arguments")
	exit
}

fndata=args[1]
tdata=read.table(file=fndata)

sdoverall<- matrix(NA, nrow=nrow(tdata), ncol=2)
dataextra<- matrix(NA, nrow=nrow(tdata), ncol=3)
gicc<- matrix(NA, nrow=nrow(tdata), ncol=4)

f.per <- function (x,y) {
	if (y<1e-10) return (0)
	return (x/y*100)
}

r=1
inv=1
for(i in seq(1,nrow(tdata),1)) {
	sicc=sum(tdata[i,4:5])
	dicc=sum(tdata[i,6:7])
	if (dicc<1e-10) {
		inv<-inv+1
		next
	}
	cursd <- c(f.per(sicc,tdata[i,1]), f.per(dicc,tdata[i,3]))
	sdoverall[r,] <- cursd 

	curdataextra<- c(f.per(tdata[i,8],dicc), f.per(tdata[i,9],dicc), f.per(tdata[i,10],dicc))
	dataextra[r,] <- curdataextra 

	curgicc<- c(f.per(tdata[i,11]+tdata[i,12],dicc), f.per(tdata[i,13]+tdata[i,14],dicc), f.per(tdata[i,15]+tdata[i,16],dicc), f.per(tdata[i,17]+tdata[i,18],dicc))
	gicc[r,] <- curgicc 

	r <- r+1
}

print(paste(inv," invalid data points ignored."))

fndatainter=args[2]
tdatainter=read.table(file=fndatainter)

sdoverallinter<- matrix(NA, nrow=nrow(tdata), ncol=2)
dataextrainter<- matrix(NA, nrow=nrow(tdatainter), ncol=3)
ginterICC<- matrix(NA, nrow=nrow(tdatainter), ncol=4)

r=1
inv=1
for(i in seq(1,nrow(tdatainter),1)) {
	sinterICC=sum(tdatainter[i,4:5])
	dinterICC=sum(tdatainter[i,6:7])
	if (dinterICC<1e-10) {
		inv<-inv+1
		next
	}
	cursd <- c(f.per(sinterICC,tdatainter[i,1]), f.per(dinterICC,tdatainter[i,3]))
	sdoverallinter[r,] <- cursd 

	curdataextra<- c(f.per(tdatainter[i,8],dinterICC), f.per(tdatainter[i,9],dinterICC), f.per(tdatainter[i,10],dinterICC))
	dataextrainter[r,] <- curdataextra 

	curginterICC<- c(f.per(tdatainter[i,11]+tdatainter[i,12],dinterICC), f.per(tdatainter[i,13]+tdatainter[i,14],dinterICC), f.per(tdatainter[i,15]+tdatainter[i,16],dinterICC), f.per(tdatainter[i,17]+tdatainter[i,18],dinterICC))
	ginterICC[r,] <- curginterICC 

	r <- r+1
}

print(paste(inv," invalid inter data points ignored."))

colors2<-c("gray","gray")
colors3<-c("red","green","red","green","red","green") 
colors4<-c("red","green","red","green","red","green","red","green") 

pdf("./gicc-dboth.pdf",width=2.5,height=3.0)
dboth <- cbind ( sdoverall[,2], sdoverallinter[,2] )
boxplot(dboth, names=c("single-app","inter-app"),col=colors2,ylab="percentage (instance view)",range=0,cex.axis=0.4,lwd=0.3,cex.lab=0.5)
meandboth <- (colMeans(dboth, na.rm=TRUE))
points(meandboth, col="gold", pch=18, cex=0.5)
stddboth <- apply( dboth, 2, sd )
print(meandboth)
print(stddboth)

pdf("./gicc-databoth.pdf",width=2.5,height=3.0)
dataextraboth <- cbind ( dataextra[,1],dataextrainter[,1], dataextra[,2],dataextrainter[,2], dataextra[,3],dataextrainter[,3] )
boxplot(dataextraboth, names=c("data only","","extras only","","both",""),col=colors3,ylab="percentage (instance view)",range=0,cex.axis=0.4,lwd=0.3,cex.lab=0.5)
meandataextraboth <- (colMeans(dataextraboth, na.rm=TRUE))
points(meandataextraboth, col="gold", pch=18, cex=0.5)
legend("top", legend=c("single-app", "inter-app"), cex=.5, col=c("red","green"), lwd=.8, bty="n",horiz=TRUE)

pdf("./gicc-iccboth.pdf",width=4.1,height=3.0)
giccboth <- cbind ( gicc[,1],ginterICC[,1], gicc[,2],ginterICC[,2], gicc[,3],ginterICC[,3], gicc[,4],ginterICC[,4] )
boxplot(giccboth, names=c("int_ex","","int_im","","ext_ex","","ex_im",""),col=colors4,ylab="percentage (instance view)",range=0,cex.axis=0.4,lwd=0.3,cex.lab=0.5)
meangiccboth <- (colMeans(giccboth, na.rm=TRUE))
points(meangiccboth, col="gold", pch=18, cex=0.5)
legend("top", legend=c("single-app", "inter-app"), cex=.5, col=c("red","green"), lwd=.8, bty="n",horiz=TRUE)

#dev.off

