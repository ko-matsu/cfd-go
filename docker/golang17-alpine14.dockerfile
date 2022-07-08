FROM golang:1.17-alpine3.14

WORKDIR /workspace

RUN apk add --update --no-cache musl gcc g++ make git cmake

RUN git config --global --add safe.directory /workspace \
  && git config --global --add safe.directory /workspace/external/cfd \
  && git config --global --add safe.directory /workspace/external/cfd-core \
  && git config --global --add safe.directory /workspace/external/libwally-core \
  && git config --global --add safe.directory /workspace/external/libwally-core/src/secp256k1
