#!/usr/bin/env python

import re,argparse,sys,os,time,ConfigParser
import tempfile
from prettytable import PrettyTable
file = tempfile.NamedTemporaryFile(delete=False)
nstemplate = file.name
try:
    import MySQLdb
except ImportError:
    sys.exit("The python MySQLdb module is required")
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("__bindadmin__")

named_file = '/etc/named.conf'

rndckey = 'rndc-key:ZwVrlhCWkVyRStQxe0ajsQ=='
nsupdate = '/usr/bin/nsupdate'
zonepath = '/var/named/chroot/var/named/'
rndc = '/usr/sbin/rndc'
checkzone = '/usr/sbin/named-checkzone'
dnsmaster = 'localhost'
archive_dir = '/var/tmp/zonemanage_archive/'
authoremail = 'ravibhure@gmail.com'
now = time.strftime("%Y%d%m%H%M%S")

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

def fixup_z_type(z_type):
     #return z_type == "master" and "master" or z_type
     if z_type == "master":
        return z_type

def parse_named_file(named_file, zone):
    """
    zone "colo" IN {
            type master;
            file "colo.zonefile";
            notify yes;
            allow-transfer { "my_networks"; };

    };
    """
    try:
        f = open(named_file, "r").read()
        pat = re.compile('zone\s+[\'"]?(\S+?)[\'"]?\s*IN?\s*{.*?type\s+[\'"]?([^\'";]+?)[\'"]?\s*;.*?file\s+[\'"]?([^\'";]+?)[\'"]?\s*;.*?;', re.DOTALL | re.MULTILINE)
        for z in pat.finditer(f):
            z = list(z.groups())
            z[1] = fixup_z_type(z[1])
            if z[0] == zone:
                return z
                #return True

    except Exception, e:
        raise
    except Exception, e:
        sys.stderr.write("Can't parse a namedfile %s: %s\n" % (named_file, e))
        sys.exit(1)

def find_hostname(zone, name):
    """ Parse valid hostname from fqdn """

    single_dot = "."

    if zone in name:
        # Find hostnames but move root zone to start of list
        name = name.split(zone)
        name = "".join(name)[:-1]
        if name.endswith(single_dot):
            name = name.strip(single_dot)

    else:
        # Find hostnames
        if name.endswith(single_dot):
            name = name.strip(single_dot)

    return name

def revName(address):
    """ Test """
    #reverse fields in IP address for use with in-addr.arpa query
    fields = address.split('.')
    fields.reverse()
    flippedaddr = '.'.join(fields)
    name = flippedaddr
    return "%s.in-addr.arpa." % name

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

def check(sql):
    """
    Executes a mysql command by sending a query to a MySQL database server,
    to fetch the given search content.
    """

    conn = dbconnection()
    mysql = conn.cursor()

    buffer = ""
    try:
        mysql.execute(sql)
        result = ''
        rows = ''
        x = PrettyTable(["Record Name", "Record Type", "Result Value"])
        x.align["Record Name"] = "l" # Left align city names
        x.padding_width = 1 # One space between column edges and contents (default)
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
                x.add_row([name, type, content])
            #print x
            return x
            return (name, type, content)
        else:
            raise
    except Exception, ex:
        logger.error(" This may be if you are trying to search incorrect 'object', which is not present into the zone db.")
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
        file.write(b"server %s\n" % dnsmaster)
        #file.write("debug yes\n")
        file.write(b"zone %s.\n" % zone)
        if action == 'add':
           file.write(b"update add %s\n" % data)
        if action == 'delete':
           file.write(b"update delete %s\n" % data)
        #file.write("show\n")
        file.write(b"send\n")
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
	   if os.path.exists(nstemplate):  # verify if file is exists
	      os.unlink(nstemplate)   # delete the tempfile
        else:
           raise
    except Exception, ex:
        logger.error(" Error: while nsupdate to '%s' zone" % zone)
        sys.exit(1)

def validation(zoneid, name, zone, type, content):
    """
    Executes a mysql command by sending a query to
    validate match case for given record and name.
    """

    conn = dbconnection()
    mysql = conn.cursor()

    buffer = ""
    # verified me

    sql = """ select * from records where domain_id='%s' and name="%s.%s" and type="%s" """ % (zoneid, name, zone, type)

    try:
        mysql.execute(sql)
        rows = ''
        rows=mysql.fetchall()
        mysql.close()
        conn.close()
        if rows:
          for fields in rows:
              already_in = fields[2]
              type = fields[3]
              contentm = fields[4]
              if content == contentm:
                 logger.error(" Error - '%s' record for '%s' with similar content '%s' already found in zone db, please check and try again!" % (type, name, content))
                 sys.exit(1)
              else:
                 logger.warning(" '%s' record for '%s' with different content '%s' already found in zone db." % (type, name, contentm))
    except Exception, ex:
        return 0
    else:
        return 0

