FROM golang:1.17-alpine3.14

WORKDIR /workspace

RUN apk add --update --no-cache musl gcc g++ make swig git cmake

COPY Makefile .
COPY go.mod .
COPY go.sum .

RUN make get-cache
