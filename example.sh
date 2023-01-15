#!/usr/bin/env bash

set -e 

# Example FreeBSD shell script for setting up and executing the RPZ processor, then restarting BIND.
# (should be easily adaptable to other *nix environments)

# Set to your latest Python >= 3.8 version.  This should be the bare executable name known to 'env', NOT a full path.
PYTHON=python3.8

# Path to the virtual environment you want to use.  If it does not exist, it will be created.
VENV=venv

# We need to be root to restart BIND later.

if [ `whoami` != 'root' ]
then
  echo This script should be run by root.
  exit 1
fi

# Set up the virtual environment if it isn't already there

if [ ! -d ${VENV} ]
then
  echo 'Creating virtual environment...'
  /usr/bin/env ${PYTHON} -m venv ${VENV} 
  source ${VENV}/bin/activate
  pip install --upgrade pip
  pip install -r requirements.txt
else
  echo 'Using existing virtual environment...'
  source ${VENV}/bin/activate
fi 

echo Using interpreter at `which ${PYTHON}`

# Run the RPZ processor as the bind user
${PYTHON} lib/main.py -U bind -c wildcards -u https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/multi.txt

deactivate

# Restart BIND
service named reload
