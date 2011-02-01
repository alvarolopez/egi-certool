#!/bin/bash

/bin/sleep 1m
echo
/bin/hostname
echo
date
/usr/sbin/ntpdate -q hora.rediris.es
echo
export
echo

