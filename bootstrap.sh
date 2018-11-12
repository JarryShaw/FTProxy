#!/usr/bin/env bash

# print a trace of simple commands
set -x

# install requirements
if [[ ! -z $( which apt-get ) ]] ; then
    sudo apt-get update && \
    sudo apt-get install -y \
        git \
        libpcap-dev \
        python3 \
        python3-pip \
        scons && \
    sudo --set-home python3 -m pip install --upgrade \
        pip \
        wheel \
        setuptools \
        pipenv
elif [[ ! -z $( which yum ) ]] ; then
    sudo yum update && \
    sudo yum install -y \
        git \
        libpcap-dev \
        python3 \
        python3-pip \
        scons & \
    sudo --set-home python3 -m pip install --upgrade \
        pip \
        wheel \
        setuptools \
        pipenv
else
    sudo --set-home python3 -m pip install --upgrade \
        pip \
        wheel \
        setuptools \
        pipenv
    returncode=$?
    if [[ $returncode -ne "0" ]] ; then
        exit $returncode
    fi
fi

# prepare Pipenv
pipenv install
