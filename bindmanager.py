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

# generator only to read nonblank lines
def nonblank_lines(f):
    for l in f:
        line = l.rstrip()
        if line:
            yield line

with open(path) as file:
    for line in nonblank_lines(file):
        fields = line.strip().split()
        domain_id = fields[1]
        name = fields[2]
        type = fields[3]
        content = fields[4]
        ttl = fields[5]
        get_list =  (name + '.', ttl, 'IN', type, content)
#        print " ".join(get_list)

with open(path) as file:
    for line in nonblank_lines(file):
        if "SOA" in line:
           fields = line.strip().split()
           name = fields[2]
           type = fields[3]
           content = fields[4]
           admin = fields[5]
           serial = fields[6]
           refresh = fields[7]
           retry = fields[8]
           expire = fields[9]
           minimum = fields[10]
           ttl = fields[11]
           get_soa =  (name + '.', ttl, 'IN', type, content, admin, serial, refresh, retry, expire, minimum)
           mysoa = " ".join(get_soa)
           print mysoa
        if "NS" in line:
           fields = line.strip().split()
           name = fields[2]
           type = fields[3]
           content = fields[4]
           get_ns =  (name + '.', ttl, 'IN', type, content + '.')
           myns = " ".join(get_ns)
           # List NS record
           try:
             myns
           except NameError:
             print "; well, it WASN'T defined after all!"
           else:
             print myns
        if "MX" in line:
           fields = line.strip().split()
           name = fields[2]
           type = fields[3]
           content = fields[4]
           get_mx =  (name + '.', ttl, 'IN', type, content)
           # List MX record
           try:
             mymx
           except NameError:
             print "; well, it WASN'T defined after all!"
           else:
             print mymx
        if "A" in line and 'SOA' not in line and 'CNAME' not in line:
           fields = line.strip().split()
           name = fields[2]
           type = fields[3]
           content = fields[4]
           get_a =  (name + '.', ttl, 'IN', type, content)
           mya = " ".join(get_a)
           # List A record
           try:
             mya
           except NameError:
             print "; well, it WASN'T defined after all!"
           else:
             print mya
        if "CNAME" in line:
           fields = line.strip().split()
           name = fields[2]
           type = fields[3]
           content = fields[4]
           get_cname =  (name + '.', ttl, 'IN', type, content + '.')
           mycname = " ".join(get_cname)
           # List CNAME record
           try:
             mycname
           except NameError:
             print "; well, it WASN'T defined after all!"
           else:
             print mycname
