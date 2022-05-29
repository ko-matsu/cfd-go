@echo off
setlocal
set PATH=%PATH%;%~dp0%\build\Release;
call go test -p 1 -count=1 . ./types/... ./errors ./utils ./config ./apis/... ./service/... ./tests -v
