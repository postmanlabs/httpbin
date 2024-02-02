#!/bin/bash

set -xeuo pipefail

ecr_login_presidio() {
  aws --profile deploy --region ${AWS_REGION:-us-east-1} ecr get-login-password |
    docker login \
    --username AWS \
    --password-stdin \
    ${AWS_ACCOUNT_ID:-190066226418}.dkr.ecr.${AWS_REGION:-us-east-1}.amazonaws.com
}

ecr_login_presidio