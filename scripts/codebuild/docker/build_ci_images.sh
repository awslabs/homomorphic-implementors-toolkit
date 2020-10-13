#!/bin/bash -ex
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

if [ -z ${1+x} ]; then
  ECS_REPO="465824340922.dkr.ecr.us-west-2.amazonaws.com/hit-codebuild"
else
  ECS_REPO=$1
fi

echo "Uploading docker images to ${ECS_REPO}."

$(aws ecr get-login --no-include-email --region us-west-2)

docker build -f ubuntu-18.04_base.docker -t ubuntu-18.04:base .
docker tag ubuntu-18.04:base ${ECS_REPO}:ubuntu-18.04_base

docker build -f ubuntu-18.04_gcc-9x.docker -t ubuntu-18.04:gcc-9x .
docker tag ubuntu-18.04:gcc-9x ${ECS_REPO}:ubuntu-18.04_gcc-9x

docker build -f ubuntu-18.04_clang-10x.docker -t ubuntu-18.04:clang-10x .
docker tag ubuntu-18.04:clang-10x ${ECS_REPO}:ubuntu-18.04_clang-10x

# docker push ${ECS_REPO}:ubuntu-18.04_base
# docker push ${ECS_REPO}:ubuntu-18.04_gcc-9x
# docker push ${ECS_REPO}:ubuntu-18.04_clang-10x
