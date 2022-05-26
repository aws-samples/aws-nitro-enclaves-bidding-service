# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

FROM amazonlinux:2

WORKDIR /usr/src/app

RUN yum install -y python3

COPY vsock-poc.py .
COPY kmstool_enclave_cli .
COPY libnsm.so /usr/lib64/

CMD ["python3", "/usr/src/app/vsock-poc.py", "enclave", "5005"]
