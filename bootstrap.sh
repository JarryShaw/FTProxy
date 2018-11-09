#!/usr/bin/env bash

# print a trace of simple commands
set -x

# install requirements
sudo apt-get update && \
sudo apt-get install -y \
    git \
    net-tools \
    python3 \
    python3-pip && \
sudo --set-home python3 -m pip install --upgrade \
    pip \
    wheel \
    setuptools \
    ipython \
    pipenv

# prepare Pipenv
git clone https://github.com/JarryShaw/FTProxy.git ~/Desktop
cd ~/Desktop/FTProxy
pipenv install
