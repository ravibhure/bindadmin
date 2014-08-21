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

from lib.bind import *
myname = os.path.basename(__file__)

def zonedetails(zone):
    """
    Executes a mysql command by sending a query to a MySQL database server.
    """

    # Get the zone id
    conn = dbconnection()
    mysql = conn.cursor()
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
        logger.error(" Error fetching result - no '%s' zone available, please provide correct zone name" % zone)
        sys.exit(1)

def execute(sql):
    """
    Executes a mysql command by sending a query to a MySQL database server.
    """

    conn = dbconnection()
    mysql = conn.cursor()

    buffer = ""
    # Database action

    try:
        mysql.execute(sql)
        rows = ''
        mysql.close()
        conn.close()
	return "Task Done"
    except Exception, ex:
        logger.error(" Error while updating database")
        sys.exit(1)

def show(args):
    """
    Figure out server IP or name for a given 'zone'.
    Raise an exception if no suitable record is found.
    """


    zone = args.zone.lower()
    zoneid = zonedetails(zone)
    content = args.content
    name = args.name
    list = args.list
    try:
        if content:
           pass
        elif name:
           pass
        elif list:
           pass
        else:
           raise
    except Exception, ex:
	logger.error(" At least one from 'name' or 'content' required while looking for any object.")
	logger.info(" Usages: %s show -h" % myname)
	sys.exit(1)

    # Parse hostname

    try:
        if name:
	    is_valid = re.match("^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$", name)
	    if is_valid:
		search = name.lower()
		search = find_hostname(zone, search)
                sql = """ select * from records where domain_id='%s' and name='%s.%s' """ % (zoneid, search, zone)
	    else:
		raise
        elif content:
	    search = content
            sql = """ select * from records where domain_id='%s' and content='%s' """ % (zoneid, search)
	elif list:
            sql = """ select * from records where domain_id='%s' """ % (zoneid)
    except Exception, ex:
        logger.error(" Error - While searching given value, probabily it is not valid '%s', '%s'" % (name, content))
        sys.exit(1)

    print check(sql)

def addrecord(args):
    """ Connects to the zone specified by the user and add record to its fields. """
    name = args.name.lower()
    type = args.type.upper()
    content = args.content
    zone = args.zone.lower()
    zoneid = zonedetails(zone)

    # Parse hostname
    name = find_hostname(zone, name)

    # Validation..valdation and more
    try:
        if name:
            is_valid = re.match("^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$", name)
            if is_valid:
              try:
                  if type in SUPPORTED_RECORD_TYPES:
                      if type == 'A':
                        try:
                            if content:
                                is_valid = re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", content)
                                if is_valid:
                                    validation(zoneid, name, zone, type, content)
                                else:
                                    raise
                            else:
                                raise
                        except Exception, ex:
                            logger.error(" Error - '%s' is not a valid ip" % content)
			    sys.exit(1)
                      elif type == 'CNAME':
                        try:
                            if content:
                                is_valid = re.match("^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$", content)
                                if is_valid:
                                    validation(zoneid, name, zone, type, content)
                                else:
                                    raise
                            else:
                                raise
                        except Exception, ex:
                            logger.error(" Error - '%s' is not a valid hostname" % content)
                            sys.exit(1)
                      else:
                        validation(zoneid, name, type, content)
                        pass
                  else:
                      raise
              except Exception, ex:
                  logger.error(" Error - '%s' is not a valid record type, reffer one from '%s'" % (type, SUPPORTED_RECORD_TYPES))
                  sys.exit(1)
            else:
                raise
        elif content:
            is_valid = re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", ip)
            if is_valid:
                pass
            else:
                raise
    except Exception, ex:
        logger.error(" Error - '%s', probabily it is not valid hostname/ip" % name)
        sys.exit(1)

    if args.ttl:
	ttl = args.ttl
    else:
	ttl = '86400'
    sql =  """ insert into records (domain_id, name,type,content,ttl,prio) select id, '%s.%s', '%s', '%s', '%s', 0 from domains where id='%s' """ % (name, zone, type, content, ttl, zoneid)

    result = execute(sql)
    logger.info("%s - added record '%s' successfully" % (result, name))
    action = 'add'
    data = "%s.%s. %s %s %s" % (name, zone, ttl, type, content)
    nsfile(action, zone, data)

    archivezone(zone)
    dnsupdate(zone)
    if check_zone(zonepath, zone):
        logger.info("Sanity check went good for '%s'" % zone)
        reloadzone(zone)
        return True
    else:
        revertzone(zone)
        reloadzone(zone)
        raise
        logger.error(" Error: in '%s' zone file, please check, we have reverted to fixed it" % zone)
        sys.exit(1)


def deleterecord(args):
    """ Connects to the zone specified by the user and delete record to its fields. """
    name = args.name.lower()
    zone = args.zone.lower()
    type = args.type.upper()
    zoneid = zonedetails(zone)

    # Parse hostname
    name = find_hostname(zone, name)

    if args.content and type:
        content = args.content
        sql = """ delete from records where domain_id='%s' and name='%s.%s' and content='%s' and type='%s' """ % (zoneid, name, zone, content, type)
	data = "%s.%s. %s %s" % (name, zone, type, content)
    elif type:
        try:
            if type in SUPPORTED_RECORD_TYPES:
                sql = """ delete from records where domain_id='%s' and name='%s.%s' and type='%s' """ % (zoneid, name, zone, type)
		data = "%s.%s. %s" % (name, zone, type)
            else:
                raise
        except Exception, ex:
            logger.error(" Error - '%s' is not a valid record type, reffer one from '%s'" % (type, SUPPORTED_RECORD_TYPES))
            sys.exit(1)
    else:
        sql = """ delete from records where domain_id='%s' and name='%s.%s' """ % (zoneid, name, zone)

    result = execute(sql)
    logger.info("%s - removed record(s) '%s' successfully" % (result, name))
    ttl = '86400'
    action = 'delete'
    nsfile(action, zone, data)

    archivezone(zone)
    dnsupdate(zone)
    if check_zone(zonepath, zone):
        logger.info("Sanity check went good for '%s'" % zone)
        reloadzone(zone)
        return True
    else:
        revertzone(zone)
        reloadzone(zone)
        raise
        logger.error(" Error: in '%s' zone file, please check, we have reverted to fixed it" % zone)
        sys.exit(1)

def main():
    """
    Figure out what you want to do from bindadmin, and then do the
    needful (at the earliest).
    """
    parser = argparse.ArgumentParser(description="Queries the zone database for Build information", epilog="To know more, write to: %s" % authoremail)
    subparsers = parser.add_subparsers()

    # toggle show record
    parser_show = subparsers.add_parser('show',help="show's your defined search from given zone")
    parser_show.add_argument("-z", "--zone", help="Set the zone to be check",required=True)
    parser_show.add_argument("-n", "--name", help="The record name to be check",required=False)
    parser_show.add_argument("-c", "--content", help="The record value or ip address to be check",required=False)
    parser_show.add_argument("-l", "--list", action='store_true', help="List all record values for specified zone",required=False)
    parser_show.set_defaults(func=show)

    # toggle add record
    parser_add  = subparsers.add_parser('add', help="Add the given record to the zone")
    parser_add.add_argument("-n", "--name", help="The record name to add",required=True)
    parser_add.add_argument("-t", "--type", help="The record type to add for record name",required=True)
    parser_add.add_argument("-c", "--content", help="The record value to add for record name",required=True)
    parser_add.add_argument("-tl", "--ttl", help="The record ttl to add for record name",required=False)
    parser_add.add_argument("-z", "--zone", help="Set the zone to be updated",required=True)
    parser_add.set_defaults(func=addrecord)

    # toggle delte record
    parser_delete  = subparsers.add_parser('delete', help="Remove the given record from the zone(s)")
    parser_delete.add_argument("-n", "--name", help="The record name to delete",required=True)
    parser_delete.add_argument("-t", "--type", help="The record type to delete for record name",required=True)
    parser_delete.add_argument("-c", "--content", help="The record value to add for record name",required=False)
    parser_delete.add_argument("-z", "--zone", help="Set the zone to be updated",required=True)
    parser_delete.set_defaults(func=deleterecord)

    args = parser.parse_args()

    args.func(args)
    return 0

# +----------------------------------------------------------------------+

if __name__ == "__main__":
    sys.exit(main())
