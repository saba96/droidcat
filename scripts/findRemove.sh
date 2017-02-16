#!/bin/bash

find . -name "$1" -type d -exec rm -r "{}" \;
