rm(list = ls())

args = commandArgs(trailingOnly = T)
if (is.na(args[1])) {
 cat("WARNING - no config file specified, using default\n")
 source("conf.R")
} else {
  conf_name=args[1]
  if (!any(grep("*\\.R$",conf_name,ignore.case=T))){
    conf_name=paste0(conf_name,".R")
  }
  source(conf_name)
}

source("shared.R")
library("e1071")
library("kernlab")  
score_file=get_score_file()
output=get_full_name()
results_file=get_results_file()

split_data_train_test <- function(data, n, traindata,testdata) {
  results = list()
  if (n==1){
    results[[1]] = list(trainset=traindata,testset=data)
    return(results)
  }
  parts = split(traindata, sample(rep(1:n, nrow(traindata)/n)))
  fold = 0
  for (part in parts){
    fold = fold + 1
    testset = part
    testset = rbind(testset, testdata)
    trainset = traindata[!rownames(traindata) %in% rownames(part),]
    results[[fold]] = list(trainset=trainset,testset=testset)
  }
  return(results)
}

split_data_features_metadata <- function(data){
  meta_features_col = c(grep("^name|^cl|^malic", names(data)))
  data_is_metadata <- 1:ncol(data)
  features <- (data[, -meta_features_col])
  metadata <- data[, meta_features_col]
  return(list(features=features,metadata=metadata))
} 
############
if (loadRDS){
  data = readRDS(file=to_rds(score_file))
}else{
  data = read.csv(file=score_file, head=TRUE, sep=";")
}
print("data loaded")
sink(paste0(path,output,".txt"))
print(score_file)

rownames(data)<-data$name

mdata=data
malic = mdata[mdata$malicious == 1,]
benign = mdata[mdata$malicious == 0,]
cat("m:",nrow(malic),"b:",nrow(benign),"\n")
cat("size: ",dim(mdata),"\n")
run_res=list()
for (iter in 1:n.runs) {
  data_set = split_data_train_test(mdata, n.folds, benign, malic)
  results_fold = list()  
  cat("run: ",iter,"\n")
  for(fold in 1:n.folds){    
    sfdata = data_set[[fold]]
    sfmdata_train = split_data_features_metadata(sfdata$trainset)
    sfmdata_test = split_data_features_metadata(sfdata$testset)

    test.data=sfmdata_test$features
    training.data = sfmdata_train$features

    test.metadata=sfmdata_test$metadata
    cat("train ",nrow(training.data)," test ",nrow(test.data),"\n")
    sigdata=as.matrix(training.data)
    gamma=sigest(sigdata,scaled=scale)
    gamma=mean(gamma)
    if (is.na(gamma)){
      gamma=0.1# normally we should not reach this line
    }
    model = svm(training.data, type="one-classification",nu=nu, scale=scale, gamma=gamma)
    predict_data = predict(model, test.data, decision.values = TRUE)
    decision_values = attributes(predict_data)$decision.values

    merged_results = cbind(test.metadata,predict_data,decision_values)
    colnames(merged_results)[ncol(merged_results)-1] <- "predicted"
    colnames(merged_results)[ncol(merged_results)] <- "decision_values"
  # mispredicted means that the app is Malicious, but the classifier returned TRUE (i.e. it belongs to the distribution of the good apps) 
  # or the app is not Malicious, but the clasifier returnes FALSE (i.e. it does not belong to the distibution)
    mispredicted = merged_results[(merged_results$malicious == 0 & merged_results$predicted == FALSE) | (merged_results$malicious == 1 & merged_results$predicted == TRUE),]
    false_positives = merged_results[(merged_results$malicious == 0 & merged_results$predicted == FALSE),]
    false_negatives = merged_results[(merged_results$malicious == 1 & merged_results$predicted == TRUE),]
    true_positives = merged_results[(merged_results$malicious == 1 & merged_results$predicted == FALSE),]
    true_negatives = merged_results[(merged_results$malicious == 0 & merged_results$predicted == TRUE),]

    results_fold[[fold]] = list(model=model,
     predict_data=predict_data, 
     mispredicted=mispredicted, 
     false_positives=false_positives,
     false_negatives=false_negatives,
     true_positives=true_positives,
     true_negatives=true_negatives,
     neg_count=length(which(test.metadata$malicious==0)),
     all_test_values=merged_results
     )

    cat("FP ", nrow(results_fold[[fold]]$false_positives), " ")
    cat("FN ", nrow(results_fold[[fold]]$false_negatives), " ")
    cat("TP ", nrow(results_fold[[fold]]$true_positives), " ")
    cat("TN ", nrow(results_fold[[fold]]$true_negatives), " \n")
  }

  pos=nrow(malic)
  neg=nrow(benign)/n.folds
  tpos=mean(sapply(results_fold, function(x) nrow(x$true_positives)))
  tneg=mean(sapply(results_fold, function(x) nrow(x$true_negatives)))
  fpos=mean(sapply(results_fold, function(x) nrow(x$false_positives)))
  fneg=mean(sapply(results_fold, function(x) nrow(x$false_negatives)))

  if (printFP){
    fp_dir=get_fp_dir()
    for(fold in 1:n.folds){
      rfold=results_fold[[fold]]
      fplist=rfold$false_positives
      write.table(fplist$name,file=paste0(fp_dir,"/f_",fold,"_false_positives.txt"),quote=F,row.names=F,col.names=F)
    }

    fp_all=unlist(sapply(results_fold, function(x) x$false_positives$name))
    write.table(fp_all,file=paste0(fp_dir,"/all_false_positives.txt"),quote=F,row.names=F,col.names=F)
  }
  g=sqrt(tpos/pos*tneg/neg)
  acc=(tpos+tneg)/(pos+neg)
  tpr=tpos/pos
  tnr=tneg/neg

  cat(output,"knn",orca_knn,"nu",nu,"g",g,"acc",acc,"tpr",tpr,"tnr",tnr,"\n")
  
  run_res[[iter]]=list(
    tpos=tpos,
    tneg=tneg,
    fpos=fpos,
    fneg=fneg,
    g=sqrt(tpos/pos*tneg/neg),
    acc=(tpos+tneg)/(pos+neg),
    tpr=tpos/pos,
    tnr=tneg/neg
    )
}
sink()
pos=nrow(malic)
neg=nrow(benign)/n.folds

tpos=mean(sapply(run_res,function(x)x$tpos))
tneg=mean(sapply(run_res,function(x)x$tneg))
fpos=mean(sapply(run_res,function(x)x$fpos))
fneg=mean(sapply(run_res,function(x)x$fneg))

g=sqrt(tpos/pos*tneg/neg)
acc=(tpos+tneg)/(pos+neg)
tpr=tpos/pos
tnr=tneg/neg

precision=tpos/(tpos+fpos)
recall=tpos/(tpos+fneg)
f1=2*precision*recall/(precision+recall)

sink(results_file,append=TRUE)
cat(output,"knn",orca_knn,"nu",nu,"g",g,"acc",acc,"tpr",tpr,"tnr",tnr,"\n")
#cat(output, "precision\t", precision, "recall\t", recall, "f1\t", f1, "accuracy\t", acc,"\n")
cat(output, "precision\t", "recall\t", "f1\t", "accuracy\t","\n")
cat(output, precision, "\t", recall, "\t", f1, "\t", acc, "\n") 
sink()
cat(output,"knn",orca_knn,"nu",nu,"g",g,"acc",acc,"tpr",tpr,"tnr",tnr,"\n")
#cat(output, "precision\t", precision, "recall\t", recall, "f1\t", f1, "accuracy\t", acc,"\n")
cat(output, "precision\t", "recall\t", "f1\t", "accuracy\t","\n")
cat(output, precision, "\t", recall, "\t", f1, "\t", acc, "\n") 

###########################
