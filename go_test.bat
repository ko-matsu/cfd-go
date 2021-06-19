@echo off
setlocal
set PATH=%PATH%;%~dp0%\build\Release;
call go test . ./types/... ./apis/... ./service/... ./tests -v
