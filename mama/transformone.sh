#!/bin/bash

cat $1 | awk -F' ' '{ 
    flag=0 
    for(i=1;i<=NF;i++) { 
        if (flag==1) printf("%s ", $i) 
        else if ($i=="in") flag=1 
    }
    printf("\n")
}'
