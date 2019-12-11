#!/bin/sh -l

cd /github/workspace/dist
cp -rf usr /
ls -l /usr/local/*
ls -l /usr/local/go/bin
LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/usr/local/lib64:/usr/local/lib" /usr/local/go/bin/go test
