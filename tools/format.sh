#!/bin/sh
cd `git rev-parse --show-toplevel`

go fmt . ./types/... ./apis/... ./service/...
