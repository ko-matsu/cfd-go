FROM golang:1.19-alpine3.17

WORKDIR /workspace

# set volume: gocache, gomodcache, ccache
VOLUME ["/root/.cache/go-build", "/go/pkg/mod", "/root/.cache/ccache"]

RUN apk add --update --no-cache musl gcc g++ make swig git cmake ccache

RUN git config --global --add safe.directory /workspace \
  && git config --global --add safe.directory /workspace/external/cfd \
  && git config --global --add safe.directory /workspace/external/cfd-core \
  && git config --global --add safe.directory /workspace/external/libwally-core \
  && git config --global --add safe.directory /workspace/external/libwally-core/src/secp256k1
