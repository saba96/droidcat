#!/bin/Rscript

require(graphics)

args=commandArgs(trailingOnly=TRUE)
if (length(args)<1) {
	stop("too few arguments")
	exit
}

fndata=args[1]
tdata=read.table(file=fndata)

catdata=new.env()

for(i in 1:nrow(tdata)) {
	mykey<-paste(tdata[i,2],"->",tdata[i,3])
	if (grepl("Unknown", mykey)) {
		next
	}
	if (!(mykey %in% ls(catdata))) {
		catdata[[mykey]] <- vector() #(mode='numeric')
	}
	catdata[[mykey]] <- c(catdata[[mykey]], tdata[i,1])
	#append(catdata[[mykey]], tdata[i,1])
	#length(catdata[[mykey]])
}

pdf("./edgeFreq-scatter.pdf")
i=1
colors<-c("red","blue","black","green","yellow","darkorange","darkorchid","gold4","darkgrey")
pches<-c(0:8)
for (key in ls(catdata)) {
	#print (key)
	vdata <- catdata[[key]]
	#print (vdata)
	#summary(vdata)
	if (i==1) {
		#plot (x=c(1:length(vdata)), y=order(vdata), col=colors[i], log="xy", xlim=c(1,length(vdata)),ylim=c(1,max(vdata)))
		plot (c(1:length(vdata)), sort(vdata), col=colors[i], log="xy",pch=pches[i],xlim=c(1,1000000), ylim=c(1,1000000), xlab="Call",ylab="Frequency", cex=.3)
		legend("topleft", legend=ls(catdata), cex=.6, col=colors, lwd=2, bty="n",pch=pches)
	}
	else {
		#points(x=c(1:length(vdata)), y=order(vdata), col=colors[i], xlim=c(1,length(vdata)),ylim=c(1,max(vdata)))
		points(sort(vdata), col=colors[i],pch=pches[i], cex=.3)
	}
	i <- i+1
}

#dev.off


