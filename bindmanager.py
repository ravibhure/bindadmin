#!/usr/bin/python

'''
    This script does bind update changes of your zone, based on inputs provided by user or by reading in a CSV file,
    then Publishing the Zones that were updated trough the BIND API using zone allow rndc-key

    The credentials are read in from a configuration file in
    the same directory.

    The file is named credentials.cfg in the format:

    [binduser]
    user: user_name
    password: password

    [securekey]
    keyname: key_name
    key = XXXXXXXXXXX==

    Usage: %python bind.py [-F]

    Options
        -h, --help              Show this help message and exit
        -F, FILE, --File=FILE   Add CSV file to search through for bulk IP address change.

    This script is more clearly used stuff from following git repo written by Juned Memon:
    https://github.com/junaid18183/zonemanage
'''

import sys
import os
import csv
import ConfigParser
from optparse import OptionParser

path='sample.txt'
with open(path) as file:
    for line in file:
        fields = line.strip().split()
	domain_id = fields[1]
        name = fields[2]
        type = fields[3]
        content = fields[4]
        ttl = fields[5]
        get_list =  (name + '.', ttl, 'IN', type, content)
        print " ".join(get_list)

