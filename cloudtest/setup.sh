#!/bin/bash
# Create the cloudtest virtualenv with boto3 (run once):
#   ./setup.sh
set -eu
cd "$(dirname "$0")"
if [ ! -x ".venv/bin/python" ]; then
  python3 -m venv .venv
fi
# Some base interpreters build a venv without pip; bootstrap it explicitly.
if [ ! -x ".venv/bin/pip" ] && [ ! -x ".venv/bin/pip3" ]; then
  .venv/bin/python -m ensurepip --default-pip >/dev/null
fi
.venv/bin/python -m pip install --quiet --upgrade boto3
echo "==> boto3 ready: $("$PWD/.venv/bin/python" -c 'import boto3; print(boto3.__version__)')"