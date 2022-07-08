FROM golang:1.17-alpine3.14

WORKDIR /workspace

RUN apk add --update --no-cache musl gcc g++ make swig git cmake

COPY Makefile .
COPY go.mod .
COPY go.sum .

RUN make get-cache \
  && rm Makefile go.mod go.sum

RUN git config --global --add safe.directory /workspace \
  && git config --global --add safe.directory /workspace/external/cfd \
  && git config --global --add safe.directory /workspace/external/cfd-core \
  && git config --global --add safe.directory /workspace/external/libwally-core \
  && git config --global --add safe.directory /workspace/external/libwally-core/src/secp256k1
