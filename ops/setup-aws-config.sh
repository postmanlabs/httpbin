#!/usr/bin/env bash

mkdir -p ~/.aws

echo "
[default]
region = us-west-2
aws_access_key_id=$AWS_ACCESS_KEY_ID
aws_secret_access_key=$AWS_SECRET_ACCESS_KEY
[deploy]
region = us-east-1
role_arn = arn:aws:iam::190066226418:role/VGSImageDeploy
source_profile = default
" >> ~/.aws/credentials
