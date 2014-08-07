#!/usr/bin/env python

import re,argparse,sys,os,time,ConfigParser
try:
    import MySQLdb
except ImportError:
    sys.exit("The python MySQLdb module is required")
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("__bindadmin__")

rndckey = 'rndc-key:ZwVrlhCWkVyRStQxe0ajsQ=='
nsupdate = '/usr/bin/nsupdate'
zonepath = '/var/named/chroot/var/named/'
rndc = '/usr/sbin/rndc'
checkzone = '/usr/sbin/named-checkzone'
dnsmaster = 'localhost'
archive_dir = '/var/tmp/zonemanage_archive/'
authoremail = 'ravibhure@gmail.com'
now = time.strftime("%Y%d%m%H%M%S")
nstemplate = '/tmp/nstemplate'

SUPPORTED_RECORD_TYPES = ('A', 'CNAME', 'MX', 'NS', 'TXT', 'PTR')

def load_config_file():
    ''' Load Config File order(first found is used): ENV, CWD, HOME, /etc/bindadmin '''

    parser = ConfigParser.ConfigParser()

    path1 = os.getcwd() + "/config.cfg"
    path2 = os.path.expanduser("~/config.cfg")
    path3 = "/etc/bindadmin/config.cfg"

    for path in [path1, path2, path3]:
        if  path is not None and os.path.exists(path):
            parser.read(path)
            return parser
    return None

def load_mycnf():
    
    try:
        parser = load_config_file()
        if  parser is not None:
            parser = load_config_file()
        else:
            raise
    except Exception, e:
        logger.error(" Error - config file not found...")
        sys.exit(1)

    # We support two forms of database user passwords in config.cnf, both pass= and password=,
    # as these are both supported by MySQL.
    try:
        passwd = config_get(parser, 'database', 'dbpassword')
    except (ConfigParser.NoOptionError):
        try:
            passwd = config_get(parser, 'database', 'dbpass')
        except (ConfigParser.NoOptionError):
            return False

    # If config.cnf doesn't specify a database user, return false
    try:
        user = config_get(parser, 'database', 'dbuser')
    except (ConfigParser.NoOptionError):
        return False

    # If config.cnf doesn't specify a database name, return false
    try:
        db = config_get(parser, 'database', 'dbname')
    except (ConfigParser.NoOptionError):
        return False

    # If config.cnf doesn't specify a database host, return false
    try:
        host = config_get(parser, 'database', 'dbhost')
    except (ConfigParser.NoOptionError):
        return False
        
    #conn = MySQLdb.Connection(db=database, host=host, user=user, passwd=password)        
    creds = dict(user=user,passwd=passwd,db=db,host=host)
    return creds
 

def strip_quotes(s):
    """ Remove surrounding single or double quotes

    >>> print strip_quotes('hello')
    hello
    >>> print strip_quotes('"hello"')
    hello
    >>> print strip_quotes("'hello'")
    hello
    >>> print strip_quotes("'hello")
    'hello

    """
    single_quote = "'"
    double_quote = '"'

    if s.startswith(single_quote) and s.endswith(single_quote):
        s = s.strip(single_quote)
    elif s.startswith(double_quote) and s.endswith(double_quote):
        s = s.strip(double_quote)
    return s

def config_get(parser, section, option):
    """ Calls ConfigParser.get and strips quotes

    See: http://dev.mysql.com/doc/refman/5.0/en/option-files.html
    """
    return strip_quotes(parser.get(section, option))

def dbconnection():
    """ Create database connection to used everywhere """

    # Get the zone id
    mycnf_creds = load_mycnf()
    user = mycnf_creds["user"]
    passwd = mycnf_creds["passwd"]
    db = mycnf_creds["db"]
    host = mycnf_creds["host"]

    buffer = ""
    try:
        conn = MySQLdb.Connection(user=user, passwd=passwd, db=db, host=host)
	return conn
    except MySQLdb.OperationalError, e:
        logger.error(" Error - While connecting to database...")
        sys.exit(1)

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

def nsfile(action, zone, data):
    """
    Write record details to add to zone.
    """

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
    cmd = "%s -y '%s' -v %s > /dev/null 2>&1" % (nsupdate, rndckey, nstemplate)

    try:
        if syscall(cmd):
           logger.info("Successfully updated '%s' zone" % zone)
        else:
           raise
    except Exception, ex:
        logger.error(" Error: while nsupdate to '%s' zone" % zone)
        sys.exit(1)

