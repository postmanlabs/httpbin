#!/usr/bin/env bash

echo "saving docker images for version: [$VERSION]"
docker save -o httpbin.tar 190066226418.dkr.ecr.us-east-1.amazonaws.com/vault/httpbin:${VERSION:-latest}
