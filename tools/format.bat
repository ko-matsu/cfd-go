setlocal
@echo off
if exist "format.bat" (
  cd ..
)

CALL go fmt . ./types/... ./apis/... ./service/...
