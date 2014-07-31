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

import re,argparse,sys,os,time
try:
    import MySQLdb
except ImportError:
    sys.exit("The python MySQLdb module is required")

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

host = 'localhost'
user = 'bindadmin'
password = 'password'
database = 'dnsdb'
dnsmaster = 'localhost'
rndckey = 'rndc-key:ZwVrlhCWkVyRStQxe0ajsQ=='
nsupdate = '/usr/bin/nsupdate'
zonepath = '/var/named/chroot/var/named/'
rndc = '/usr/sbin/rndc'
checkzone = '/usr/sbin/named-checkzone'
archive_dir = '/var/tmp/zonemanage_archive/'
authoremail = 'ravibhure@gmail.com'
now = time.strftime("%Y%d%m%H%M%S")
SUPPORTED_RECORD_TYPES = ('A', 'CNAME', 'MX', 'NS', 'TXT', 'PTR')

def zonedetails(zone):
    """
    Executes a mysql command by sending a query to a MySQL database server.
    """

    buffer = ""
    try:
        conn = MySQLdb.Connection(db=database, host=host, user=user, passwd=password)
        mysql = conn.cursor()
    except MySQLdb.OperationalError, e:
        logger.error(" Error - While connecting to database...")
        sys.exit(1)
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
        logger.error(" Error fetching result - no '%s' zone available, please provide correct zone name" % zone)
        sys.exit(1)

def validation(zoneid, name, type, content):
    """
    Executes a mysql command by sending a query to a MySQL database server.
    """

    buffer = ""
    try:
        conn = MySQLdb.Connection(db=database, host=host, user=user, passwd=password)
        mysql = conn.cursor()
    except MySQLdb.OperationalError, e:
        logger.error(" Error - While connecting to database...")
        sys.exit(1)
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
         logger.error(" Error - '%s' record for '%s' with similar content '%s' already found in zone db, please check and try again!" % (type, name, content))
         sys.exit(1)
    except Exception, ex:
        return 0
    else:
        return 0


def syscall(cmd):
    """  Run system commands """

    try:
        rc = os.system(cmd)
        if rc == 0:
            return True
        else:
            return False
    except Exception, e:
        logger.error(" Shell command failed with following error: ")
        sys.exit("Error: %s" % e)

def archivezone(zone):
    """ Backup your Zone """
    if not os.path.isdir(archive_dir):
      os.makedirs(archive_dir)
    zone_file = os.path.join(zonepath, zone)
    archive_file = os.path.join(archive_dir, zone)
    cmd = "cp -f %s %s-%s" % (zone_file, archive_file, now)

    try:
        if syscall(cmd):
           logger.info("Successfully backed up '%s' zone to '%s-%s'" % (zone, archive_file, now))
        else:
           raise
    except Exception, ex:
        logger.error(" Error: while backup '%s' zone" % zone)
        sys.exit(1)

def revertzone(zone):
    """ Revert your Zone """
    if not os.path.isdir(archive_dir):
      os.makedirs(archive_dir)
    return None
    zone_file = os.path.join(zonepath, zone)
    archive_file = os.path.join(archive_dir, zone)
    cmd = "cp -f %s-%s %s" % (archive_file, now, zone_file)

    try:
        if syscall(cmd):
           logger.info("Successfully reverted '%s' zone to '%s'" % (zone, zone_file))
        else:
           raise
    except Exception, ex:
        logger.error(" Error: while reverted '%s' zone from '%s'" % (zone, archive_file))
        sys.exit(1)

def reloadzone(zone):
    """ Reload your Zone """
    cmd = "%s freeze %s > /dev/null 2>&1 && %s reload > /dev/null 2>&1 %s && %s thaw %s > /dev/null 2>&1" % (rndc, zone, rndc, zone, rndc, zone)

    try:
        if syscall(cmd):
           logger.info("Successfully reloaded '%s' zone" % zone)
        else:
           raise
    except Exception, ex:
        logger.error(" Error: while reload '%s' zone" % zone)
        sys.exit(1)

def check_zone(zonepath, zone):
    """
    Check the syntax of a zonefile by calling the named-checkzone
    binary defined in the config 'checkzone'.
    If 'checkzone' is not defined then this check is disabled
    (it always returns True).
    """
    zone_file = os.path.join(zonepath, zone)
    try:
       if os.path.isfile(zone_file):
          cmd = "%s -t %s %s %s > /dev/null 2>&1" % (checkzone, zonepath, zone, zone)
       else:
          raise
    except Exception, ex:
        logger.error(" Error: '%s' zone file does not exist at '%s', please check or adjust your zonepath" % (zone, zonepath))
        sys.exit(1)

    if syscall(cmd):
       return True
    else:
       return False


def execute(sql):
    """
    Executes a mysql command by sending a query to a MySQL database server.
    """

    buffer = ""
    try:
        conn = MySQLdb.Connection(db=database, host=host, user=user, passwd=password)
        mysql = conn.cursor()
    except MySQLdb.OperationalError, e:
        logger.error(" Error - While connecting to database...")
        sys.exit(1)
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

def nsfile(action, zone, data):
    """
    Write record details to add to zone.
    """

    nstemplate = '/tmp/nstemplate'
    try:
        file = open(nstemplate, "w")
        file.write("server %s\n" % dnsmaster)
        #file.write("debug yes\n")
        file.write("zone %s.\n" % zone)
        if action == 'add':
           file.write("update add %s\n" % data)
        if action == 'delete':
           file.write("update delete %s\n" % data)
        #file.write("show\n")
        file.write("send\n")
        file.close()
	return 0
    except Exception, ex:
        logger.error(" Error while write data to nsupdate template '%s' file" % nstemplate)
        sys.exit(1)

def dnsupdate(zone):
    """ NSupdate your Zone """
    nstemplate = '/tmp/nstemplate'
    cmd = "%s -y '%s' -v %s > /dev/null 2>&1" % (nsupdate, rndckey, nstemplate)

    try:
        if syscall(cmd):
           logger.info("Successfully updated '%s' zone" % zone)
        else:
           raise
    except Exception, ex:
        logger.error(" Error: while nsupdate to '%s' zone" % zone)
        sys.exit(1)

def check(args):
    """
    Figure out server IP or name for a given 'zone'.
    Raise an exception if no suitable record is found.
    """

    buffer = ""
    try:
        conn = MySQLdb.Connection(db=database, host=host, user=user, passwd=password)
        mysql = conn.cursor()
    except MySQLdb.OperationalError, e:
        logger.error(" Error - While connecting to database...")
        sys.exit(1)

    content = args.content
    name = args.name
    zone = args.zone
    zoneid = zonedetails(zone)
    try:
        if name:
	    is_valid = re.match("^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$", name)
	    if is_valid:
		search = name
                sql = """ select * from records where domain_id='%s' and name='%s' """ % (zoneid, search)
	    else:
		raise
        elif content:
	    search = content
            sql = """ select * from records where domain_id='%s' and content='%s' """ % (zoneid, search)
    except Exception, ex:
        logger.error(" Error - While searching given value, probabily it is not valid '%s', '%s'" % (name, content))
        sys.exit(1)

    try:
        mysql.execute(sql)
        result = ''
        rows = ''
        rows=mysql.fetchall()
        mysql.close()
        conn.close()
        if rows:
            for fields in rows:
                domain_id = fields[1]
                name = fields[2]
                type = fields[3]
                content = fields[4]
                ttl = fields[5]
            print name , '--> Record Type --> ' + type, ', Result Value --> ' + content
            return name, type, content
        else:
            raise
    except Exception, ex:
        logger.error(" Error while looking '%s', this may cause if you are trying to search incorrect 'object', which is not present into the zone db" % search)
	sys.exit(1)

def addrecord(args):
    """ Connects to the zone specified by the user and add record to its fields. """
    name = args.name
    type = args.type
    content = args.content
    zone = args.zone
    zoneid = zonedetails(zone)

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
                                    validation(zoneid, name, type, content)
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
                                    validation(zoneid, name, type, content)
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
    sql =  """ insert into records (domain_id, name,type,content,ttl,prio) select id, '%s', '%s', '%s', '%s', 0 from domains where id='%s' """ % (name, type, content, ttl, zoneid)

    result = execute(sql)
    logger.info("%s - added record '%s' successfully" % (result, name))
    action = 'add'
    data = "%s. %s %s %s" % (name, ttl, type, content)
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
    name = args.name
    zone = args.zone
    type = args.type
    zoneid = zonedetails(zone)

    if args.content and type:
        content = args.content
        sql = """ delete from records where domain_id='%s' and name='%s' and content='%s' and type='%s' """ % (zoneid, name, content, type)
	data = "%s. %s %s" % (name, type, content)
    elif type:
        try:
            if type in SUPPORTED_RECORD_TYPES:
                sql = """ delete from records where domain_id='%s' and name='%s' and type='%s' """ % (zoneid, name, type)
		data = "%s. %s" % (name, type)
            else:
                raise
        except Exception, ex:
            logger.error(" Error - '%s' is not a valid record type, reffer one from '%s'" % (type, SUPPORTED_RECORD_TYPES))
            sys.exit(1)
    else:
        sql = """ delete from records where domain_id='%s' and name='%s' """ % (zoneid, name)

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
    parser_show = subparsers.add_parser('show',help="show's your defined search from given zones")
    parser_show.add_argument("-z", "--zone", help="Set the zone to be check",required=True)
    parser_show.add_argument("-n", "--name", help="The record name to be check",required=False)
    parser_show.add_argument("-c", "--content", help="The record value or ip address to be check",required=False)
    parser_show.set_defaults(func=check)

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
