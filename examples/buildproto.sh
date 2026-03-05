#!/bin/sh
set -e

# Build Python protobuf + gRPC bindings into ./proto for the examples.
mkdir -p protocol/googleapis/google/api
mkdir -p proto

if [ ! -d protocol/tron/.git ]; then
  git clone https://github.com/tronprotocol/protocol.git protocol/tron
fi

curl -fsSL https://raw.githubusercontent.com/googleapis/googleapis/master/google/api/annotations.proto -o protocol/googleapis/google/api/annotations.proto
curl -fsSL https://raw.githubusercontent.com/googleapis/googleapis/master/google/api/http.proto -o protocol/googleapis/google/api/http.proto

python3.11 -m grpc_tools.protoc \
  -I./protocol/googleapis \
  -I./protocol/tron \
  --python_out=./proto \
  --grpc_python_out=./proto \
  ./protocol/tron/core/*.proto \
  ./protocol/tron/api/*.proto \
  ./protocol/tron/core/contract/*.proto
