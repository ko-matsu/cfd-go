.PHONY: all
all: generate format

get-cache:
	go install golang.org/x/tools/cmd/goimports@v0.1.9
	go install github.com/golang/mock/mockgen@v1.6.0
	go mod download

install-go-tools:
	$(eval BIN:=$(abspath .bin))
	mkdir -p ./.bin
	GOBIN="$(BIN)" go run ./tools/go_install.go

install-mockgen:
	$(eval BIN:=$(abspath .bin))
	mkdir -p ./.bin
	GOBIN="$(BIN)" go run ./tools/go_install.go github.com/golang/mock

update:
	go mod download all
	go mod tidy

generate:
	go generate ./apis/... ./service/...

format:
	go run golang.org/x/tools/cmd/goimports@v0.1.9 -w .
	go vet . ./types/... ./errors ./utils ./config ./apis/... ./service/... ./tests
	go mod tidy

build-lib:
	echo "build for Linux/MacOS"
	./tools/simple_build.sh

build-lib-win:
	echo "build for Windows"
	.\tools\build_mingw.bat

build-all: cleanup build-lib

build-all-win: cleanup-win build-lib-win

cleanup:
	echo "cleanup for Linux/MacOS"
	./tools/cmake_cleanup.sh

cleanup-win:
	echo "cleanup for Windows"
	.\tools\cmake_cleanup.bat

test:
	echo "test for Linux/MacOS"
	go version
	go mod download
	./go_test.sh

test-win:
	echo "test for Windows"
	go version
	go mod download
	go_test.bat

gen-swig:
	./tools/gen_swig.sh
	make format
