
format:
	go fmt . ./types/... ./errors ./utils ./config ./apis/... ./service/... ./tests
	go mod tidy

gettools:
	go get github.com/golang/mock/gomock
	go get github.com/golang/mock/mockgen
	go get golang.org/x/tools/cmd/goimports

generate:
	go generate ./apis/... ./service/...
