#!/bin/Rscript

require(graphics)

args=commandArgs(trailingOnly=TRUE)
if (length(args)<1) {
	stop("too few arguments")
	exit
}

fndata=args[1]
tdata=read.table(file=fndata)

dall<- matrix(NA, nrow=nrow(tdata), ncol=8)

f.per <- function (x,y) {
	if (y<1e-10) return (0)
	return (x/y*100)
}

r=1
inv=1
for(i in seq(1,nrow(tdata),1)) {
	if (sum(tdata[i,3:4])<1e-10) {
		inv<-inv+1
		#next
	}


	curall<- c(f.per(tdata[i,3],tdata[i,6]), f.per(tdata[i,4],tdata[i,6]), f.per(tdata[i,8],tdata[i,7]), f.per(tdata[i,9],tdata[i,7]),
               f.per(tdata[i,10],tdata[i,3]), f.per(tdata[i,11],tdata[i,4]), f.per(tdata[i,12],tdata[i,8]), f.per(tdata[i,13],tdata[i,9]))
	dall[r,] <- rev(curall)

	r <- r+1
}


dnames=c("source-callsite", "sink-callsite", "source-instance", "sink-instance", "Vul.src-callsite", "Vul.sink-callsite", "Vul.src-instance", "Vul.sink-instance")
pdf("./srcsink-all.pdf",width=4.5,height=3.0)
boxplot(dall, names=rev(dnames), range=0,cex.axis=0.4, lwd=0.3, cex.lab=0.5, col=c("gray80","green","gray80","green","gray80","green","gray80","green"), horizontal=TRUE, las=1, ylab="access", xlab="percentage")

meandall <- (colMeans(dall, na.rm=TRUE))
points(meandall, 1:8, col="red", pch=18, cex=0.5)

stddall <- apply( (dall), 2, sd )
cat(sprintf("for %d samples\n", r))
for (k in 1:ncol((dall))) {
	#print( paste(snames[k], meanalls[k], "% (", stdalls[k], "%)") )
	#cat(sprintf("%s\t%.2f%%\t%.2f%%\t%.2f%%\n", dnames[k], as.numeric(meandall[k]), as.numeric(meandall[k]-2*stddall[k]/sqrt(r)),  as.numeric(meandall[k]+2*stddall[k]/sqrt(r))))
	cat(sprintf("%s\t%.2f%%\t%.2f%%\t%.2f%%\n", dnames[k], as.numeric(meandall[k]), as.numeric(2.98*stddall[k]/sqrt(r)),  as.numeric(stddall[k]/sqrt(r))))
}
cat("\n")

#dev.off

