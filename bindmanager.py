#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''

    (c) 2014, Ravi Bhure <ravibhure@gmail.com>

    This file is part of bindadmin (https://github.com/ravibhure/bindadmin)

    This script does bind update changes of your zone, based on inputs provided by user or by reading in a CSV file,
    then Publishing the Zones that were updated trough the BIND API using zone allow rndc-key

    The credentials are read in from a configuration file in
    the same directory.

    The file is named config.cfg in the format:

    [defaults]
    user =  user_name
    password =  password

    [database]
    dbuser =  bindadmin
    dbpass =  password
    dbname =  dnsdb
    dbhost =  localhost

    [securekey]
    keyname = key_name
    key = XXXXXXXXXXX==


    Usage: %python bindmanager.py [-h]

    Options
        -h, --help              Show this help message and exit
        -F, FILE, --File=FILE   Add CSV file to search through for bulk IP address change.

    This script is more clearly used, stuff written and managed from following git repo written by Juned Memon:
    https://github.com/junaid18183/zonemanage
'''
import re,argparse,sys,os,MySQLdb

host = 'localhost'
user = 'glamdns'
password = 'password'
database = 'glamdns'

SUPPORTED_RECORD_TYPES = ('A', 'CNAME', 'MX', 'NS', 'TXT', 'PTR')

def zonedetails(zone):
    """
    Executes a mysql command by sending a query to a MySQL database server.
    """

    buffer = ""
    conn = MySQLdb.Connection(db=database, host=host, user=user, passwd=password)
    mysql = conn.cursor()
    # Get the zone id
    try:
	sql = """ select * from domains where name="%s" """ % zone
        mysql.execute(sql)
        rows = ''
        rows=mysql.fetchall()
        for fields in rows:
            id = fields[0]
            name = fields[1]
        mysql.close()
        conn.close()
        return id
    except Exception, ex:
        sys.exit("Error fetching result - no such zone available, please provide correct zone name")

def validation(zoneid, name, type, content):
    """
    Executes a mysql command by sending a query to a MySQL database server.
    """

    buffer = ""
    conn = MySQLdb.Connection(db=database, host=host, user=user, passwd=password)
    mysql = conn.cursor()
    # verified me
    sql = """ select * from records where domain_id='%s' and name="%s" and type="%s" and content="%s" """ % (zoneid, name, type, content)
    try:
      mysql.execute(sql)
      rows = ''
      rows=mysql.fetchall()
      for fields in rows:
          already_in = fields[2]
          type = fields[3]
          content = fields[4]
      mysql.close()
      conn.close()
      if already_in:
         sys.exit("Error - record already found in zone db")
    except Exception, ex:
        return 0
    else:
        return 0


def execute(sql):
    """
    Executes a mysql command by sending a query to a MySQL database server.
    """

    buffer = ""
    conn = MySQLdb.Connection(db=database, host=host, user=user, passwd=password)
    mysql = conn.cursor()
    # Database action
    try:
        mysql.execute(sql)
        rows = ''
        mysql.close()
        conn.close()
	return "Task Done"
    except Exception, ex:
        #print str(ex)
        sys.exit("Error fetching result")

def check(args):
    """
    Figure out server IP or name for a given 'zone'.
    Raise an exception if no suitable record is found.
    """

    buffer = ""
    conn = MySQLdb.Connection(db=database, host=host, user=user, passwd=password)
    mysql = conn.cursor()
    ip = args.ip
    name = args.name
    zone = args.zone
    zoneid = zonedetails(zone)
    try:
        if name:
	    is_valid = re.match("^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$", name)
	    if is_valid:
                sql = """ select * from records where domain_id='%s' and name='%s' """ % (zoneid, name)
	    else:
		raise
        elif ip:
	    is_valid = re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", ip)
	    if is_valid:
                sql = """ select * from records where domain_id='%s' and content='%s' """ % (zoneid, ip)
	    else:
		raise
    except Exception, ex:
        sys.exit("Error - While searching given value, probabily it is not valid hostname/ip")

    try:
        mysql.execute(sql)
        result = ''
        rows = ''
        rows=mysql.fetchall()
        for fields in rows:
            domain_id = fields[1]
            name = fields[2]
            type = fields[3]
            content = fields[4]
            ttl = fields[5]
        mysql.close()
        conn.close()
        print name, 'Record Type --> ' + type, ', Result Value --> ' + content
	return name, type, content
    except Exception, ex:
        #print str(ex)
        sys.exit("Error fetching search string, this may cause if you are trying to search incorrect 'object', which is not present into the zone")

def addrecord(args):
    """ Connects to the zone specified by the user and add record to its fields. """
    name = args.name
    type = args.type
    content = args.content
    zone = args.zone
    zoneid = zonedetails(zone)
    try:
        if type in SUPPORTED_RECORD_TYPES:
            validation(zoneid, name, type, content)
        else:
	    raise
    except Exception, ex:
        print "Error - '%s' is not a valid record type, reffer one from '%s'" % (type, SUPPORTED_RECORD_TYPES)
        sys.exit(1)

    if args.ttl:
	ttl = args.ttl
    else:
	ttl = '86400'
    sql =  """ insert into records (domain_id, name,type,content,ttl,prio) select id, '%s', '%s', '%s', '%s', 0 from domains where id='%s' """ % (name, type, content, ttl, zoneid)

    result = execute(sql)
    print "%s - added record '%s' successfully" % (result, name)

def deleterecord(args):
    """ Connects to the zone specified by the user and delete record to its fields. """
    name = args.name
    zone = args.zone
    zoneid = zonedetails(zone)

    if args.type:
        type = args.type
        try:
            if type in SUPPORTED_RECORD_TYPES:
                sql = """ delete from records where domain_id='%s' and name='%s' and type='%s' """ % (zoneid, name, type)
            else:
                raise
        except Exception, ex:
            print "Error - '%s' is not a valid record type, reffer one from '%s'" % (type, SUPPORTED_RECORD_TYPES)
            sys.exit(1)
    else:
        sql = """ delete from records where domain_id='%s' and name='%s' """ % (zoneid, name)

    result = execute(sql)
    print "%s - removed record(s) '%s' successfully" % (result, name)

def main():
    """
    Figure out what you want to do from bindadmin, and then do the
    needful (at the earliest).
    """
    parser = argparse.ArgumentParser(description="Queries the zone database for Build information")
    subparsers = parser.add_subparsers()

    # toggle show record
    parser_show = subparsers.add_parser('show',help="show's your defined search from given zones")
    parser_show.add_argument("-z", "--zone", help="Set the zone to be check",required=True)
    parser_show.add_argument("-n", "--name", help="The record name to be check",required=False)
    parser_show.add_argument("-i", "--ip", help="The ip address to be check",required=False)
    parser_show.set_defaults(func=check)

    # toggle add record
    parser_add  = subparsers.add_parser('add', help="Add the given record to the zone")
    parser_add.add_argument("-n", "--name", help="The record name to add",required=True)
    parser_add.add_argument("-r", "--type", help="The record type to add for record name",required=True)
    parser_add.add_argument("-v", "--content", help="The record value to add for record name",required=True)
    parser_add.add_argument("-t", "--ttl", help="The record ttl to add for record name",required=False)
    parser_add.add_argument("-z", "--zone", help="Set the zone to be updated",required=True)
    parser_add.set_defaults(func=addrecord)

    # toggle delte record
    parser_delete  = subparsers.add_parser('delete', help="Remove the given record from the zone(s)")
    parser_delete.add_argument("-n", "--name", help="The record name to delete",required=True)
    parser_delete.add_argument("-r", "--type", help="The record type to delete for record name",required=False)
    parser_delete.add_argument("-z", "--zone", help="Set the zone to be updated",required=True)
    parser_delete.set_defaults(func=deleterecord)

    args = parser.parse_args()

    args.func(args)
    return 0

# +----------------------------------------------------------------------+

if __name__ == "__main__":
    sys.exit(main())

