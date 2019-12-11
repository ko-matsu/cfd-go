#!/bin/sh -l

cd /github/workspace/dist
cp -rf usr /
ls -l /usr/local/*
export LD_LIBRARY_PATH=/usr/local/lib64:/usr/local/lib
go test
