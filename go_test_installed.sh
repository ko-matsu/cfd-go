#!/bin/sh
LD_LIBRARY_PATH=/usr/local/lib go test . ./types/... ./errors ./utils ./apis/... ./service/... ./tests
