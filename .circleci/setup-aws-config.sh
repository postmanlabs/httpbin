#!/bin/bash

mkdir -p ~/.aws

echo "
[default]
region = us-west-2
aws_access_key_id=$AWS_ACCESS_KEY_ID
aws_secret_access_key=$AWS_SECRET_ACCESS_KEY
[dev/vault]
region = us-west-2
role_arn = arn:aws:iam::883127560329:role/VGSStageDeploy
source_profile = default
[prod/vault]
region = us-east-1
role_arn = arn:aws:iam::526682027428:role/VGSStageDeploy
source_profile = default
[prod/vault-eu]
region = eu-central-1
role_arn = arn:aws:iam::526682027428:role/VGSStageDeploy
source_profile = default
[deploy]
region = us-east-1
role_arn = arn:aws:iam::190066226418:role/VGSImageDeploy
source_profile = default
" >> ~/.aws/credentials
