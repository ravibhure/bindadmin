#!/usr/bin/env python

import re,argparse,sys,os,time,ConfigParser,subprocess
from prettytable import PrettyTable
timestr = time.strftime("%Y%m%d-%H%M%S")
nstemplate = '/tmp/ns_' + timestr
ptrtemplate = '/tmp/ptr_' + timestr
try:
    import MySQLdb
except ImportError:
    sys.exit("The python MySQLdb module is required")

import logging

named_file = '/etc/named.conf'

nsupdate = '/usr/bin/nsupdate'
zonepath = '/var/named/chroot/var/named/'
rndc = '/usr/sbin/rndc'
checkzone = '/usr/sbin/named-checkzone'
dnsmaster = 'localhost'
archive_dir = '/var/tmp/zonemanage_archive/'
authoremail = 'ravibhure@gmail.com'
now = time.strftime("%Y%d%m%H%M%S")
LOGFILE='/var/log/bindadmin.log'
SUPPORTED_RECORD_TYPES = ('A', 'CNAME', 'MX', 'TXT', 'PTR')

def getlogin():
    try:
        user = os.getlogin()
    except OSError, e:
        user = pwd.getpwuid(os.geteuid())[0]
    return user

def setup_logger():
    LOG_LEVEL = logging.DEBUG
    LOG_USER = {'user': getlogin()}
    LOG_PATH = LOGFILE

    logging.root.setLevel(LOG_LEVEL)
    # Try to load the colored log and use it on success.
    # Else we'll use the SIMPLE_FORMAT
    try:
        from colorlog import ColoredFormatter
        LOGFORMAT = "  %(log_color)s%(asctime)s %(log_color)s%(name)s %(log_color)s%(user)-8s%(reset)s %(log_color)s%(levelname)-8s%(reset)s: %(log_color)s%(message)s%(reset)s"
        formatter = ColoredFormatter(LOGFORMAT)
    except ImportError:
        # Take the normal one instead.
        LOGFORMAT = "  %(asctime)s %(name)s %(user)-8s %(levelname)-8s: %(message)s"
        formatter = logging.Formatter(LOGFORMAT)
    stream = logging.StreamHandler()
    stream.setLevel(LOG_LEVEL)
    stream.setFormatter(formatter)
    fstream = logging.FileHandler(LOG_PATH)
    fstream.setLevel(LOG_LEVEL)
    fstream.setFormatter(formatter)
    logger = logging.getLogger('BINDADMIN')
    logger.setLevel(LOG_LEVEL)
    logger.addHandler(fstream)
    logger.addHandler(stream)
    logger = logging.LoggerAdapter(logger, LOG_USER)
    return logger

logger =  setup_logger()

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
        logger.error("Config file not found...")
        sys.exit(1)

    # We support two forms of database user passwords in config.cnf, both pass= and password=,
    # as these are both supported by MySQL.
    try:
        passwd = config_get(parser, 'database', 'dbpassword')
    except (ConfigParser.NoOptionError):
        try:
            passwd = config_get(parser, 'database', 'dbpass')
        except (ConfigParser.NoOptionError):
            print "No section '%s' or '%s' in config.cfg Aborting." % ('dbpassword', 'dbpass')
            sys.exit(2)

    # If config.cnf doesn't specify a database user, return false
    try:
        user = config_get(parser, 'database', 'dbuser')
        if user:
	   pass
	else:
	   raise
    except (ConfigParser.NoOptionError):
        print "No section '%s' in config.cfg Aborting." % 'dbuser'
        sys.exit(2)

    # If config.cnf doesn't specify a database name, return false
    try:
        db = config_get(parser, 'database', 'dbname')
        if db:
	   pass
	else:
	   raise
    except (ConfigParser.NoOptionError):
        print "No section '%s' in config.cfg Aborting." % 'dbname'
        sys.exit(2)

    # If config.cnf doesn't specify a database host, return false
    try:
        host = config_get(parser, 'database', 'dbhost')
        if host:
	   pass
    except (ConfigParser.NoOptionError):
        print "No section '%s' in config.cfg Aborting." % 'dbhost'
        sys.exit(2)

    # If config.cnf doesn't specify a securekey keyname, return false
    try:
        keyname = config_get(parser, 'securekey', 'keyname')
        if keyname:
	   pass
	else:
	   raise
    except (ConfigParser.NoOptionError):
        print "No section '%s' in config.cfg Aborting." % 'keyname'
        sys.exit(2)

    # If config.cnf doesn't specify a securekey key or keyfile, return false
    try:
        key = config_get(parser, 'securekey', 'key')
        if key:
	   pass
	else:
	   raise
    except (ConfigParser.NoOptionError):
        try:
            keyfile = config_get(parser, 'securekey', 'keyfile')
	    key = parse_key_file(keyfile, keyname)
        except (ConfigParser.NoOptionError):
            print "No section '%s' or '%s' in config.cfg Aborting." % ('key', 'keyfile')
            sys.exit(2)

    creds = dict(user=user,passwd=passwd,db=db,host=host,keyname=keyname,key=key)
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
        logger.error("While connecting to database...")
        sys.exit(1)

def parse_key_file(key_file, key_name):
    """
    Name server secure key file, in below format

    key "rndc-key" {
            algorithm hmac-md5;
            secret "ZwVrlhCWkVyRStQxe0ajsQ==";
    };

    We need expect to return key pair in well formated
    >>   rndc-key:ZwVrlhCWkVyRStQxe0ajsQ==
    """

    try:
        f = open(key_file, "r").read()
        pat = re.compile('key\s+[\'"]?(\S+?)[\'"]?\s*{.*?algorithm\s+[\'"]?([^\'";]+?)[\'"]?\s*;.*?secret\s+[\'"]?([^\'";]+?)[\'"]?\s*;.*?};', re.DOTALL | re.MULTILINE)
        for key in pat.finditer(f):
            key = list(key.groups())
            key[1] = fixup_key_algo(key[1])
            if key[1] and key[0] == key_name:
                return key[2]
        sys.stderr.write("Can't parse '%s' in keyfile '%s' or bad key algorithm\n" % (key_name, key_file))
        sys.exit(1)

    except Exception, e:
        raise
    except Exception, e:
        sys.stderr.write("Can't parse a keyfile %s: %s\n" % (key_file, e))
        sys.exit(1)

def fixup_key_algo(key_algo):
    if key_algo == "hmac-md5":
      return key_algo == "hmac-md5" and "HMAC-MD5.SIG-ALG.REG.INT" or key_algo

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
	    allow-update { key "rndc-key"; };

    };
    """
    try:
        f = open(named_file, "r").read()
        if re.match("^[0-9]+.*", zone):
             pat = re.compile('zone\s+[\'"]?(\S+?)[\'"]?\s*?\s*{.*?type\s+[\'"]?([^\'";]+?)[\'"]?\s*;.*?file\s+[\'"]?([^\'";]+?)[\'"]?\s*;.*?;', re.DOTALL | re.MULTILINE)
        else:
             pat = re.compile('zone\s+[\'"]?(\S+?)[\'"]?\s*IN?\s*{.*?type\s+[\'"]?([^\'";]+?)[\'"]?\s*;.*?file\s+[\'"]?([^\'";]+?)[\'"]?\s*;.*?;', re.DOTALL | re.MULTILINE)
        for z in pat.finditer(f):
            z = list(z.groups())
            if z[0] == zone and z[1] == 'slave':
                logger.error("Gotcha.. '%s' zone found as slave, sorry we can't supports slave now." % zone)
                sys.exit(1)
            # type should be 'master' or 'native'
            elif z[0] == zone:
                return z
                return True
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
    """
    Reverse fields in IP address for use with in-addr.arpa query
    """

    flippedaddr = '.'.join(reversed(address.split('.')))
    return "%s.in-addr.arpa." % flippedaddr

def revzoneName(address):
    """
    >>> print revzoneName('195.185.1.1')
    >>> print revzoneName('195.185.1.11')
    >>> print revzoneName('195.185.1.111')
    """

    fields = address.split('.')
    fields = fields[:3]
    fields.reverse()
    flippedaddr = '.'.join(fields)
    zonename = "%s.in-addr.arpa" % flippedaddr
    return zonename

def syscall(cmd):
    """  Run system commands """

    try:
        rc = os.system(cmd)
        if rc == 0:
            return True
        else:
            return False
    except Exception, e:
        logger.error("Command failed with following error: ")
        sys.exit("Error: %s" % e)

def archivezone(zone):
    """ Backup your Zone with Git """

    gitInit(zonepath)
    message="Updated %s with record" % zone

    try:
        if gitAdd(zone, zonepath):
	   if gitCommit(message, zonepath):
	      # gitPush(zonepath)
	      latestcommit = gitHEAD(zonepath)
              #logger.info("Successfully commited - %s" % latestcommit.strip())
              logger.info("Successfully commited - %s" % latestcommit)
    except Exception, ex:
        logger.error("While adding '%s' zone to git, please fix manually to verify" % zone)
        sys.exit(1)

def revertzone(zone):
    """ Revert your Zone """

    gitInit(zonepath)

    try:
        if gitReset(zonepath):
           #gitClean(zonepath)
           #gitPull(zonepath)
           logger.info("Successfully reverted '%s' zone from git" % zone)
    except Exception, ex:
        logger.error("While reverted '%s' zone from git" % zone)
        sys.exit(1)

def reloadzone(zone):
    """ Reload your Zone """
    cmd = "%s freeze %s >/dev/null 2>&1 && %s reload %s >/dev/null 2>&1 && %s thaw %s >/dev/null 2>&1" % (rndc, zone, rndc, zone, rndc, zone)
    try:
        if syscall(cmd):
           logger.info("Successfully reloaded '%s' zone" % zone)
        else:
           revertzone(zone)
           raise
    except Exception, ex:
        logger.error("While reload '%s' zone, hence reload to latest HEAD" % zone)
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
            return x
        else:
            raise
    except Exception, ex:
        logger.error("This may be if you are trying to search incorrect 'object', which is not present into the zone db.")
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
        logger.error("'%s' zone file does not exist at '%s', please check or adjust your zonepath" % (zone, zonepath))
        sys.exit(1)

    if syscall(cmd):
       return True
    else:
       return False

def nsfile(action, zone, data, nfile=nstemplate):
    """
    Write record details to add to zone.
    """
    try:
      with open(nfile, 'w') as file:
        file.write(b"server %s\n" % dnsmaster)
        file.write(b"zone %s.\n" % zone)
        if action == 'add':
           file.write(b"update add %s\n" % data)
        if action == 'delete':
           file.write(b"update delete %s\n" % data)
        file.write(b"send\n")
        file.close()
        return 0
    except Exception, ex:
        logger.error("While write data to nsupdate template '%s' file" % nfile)
        sys.exit(1)

def dnsupdate(zone, nfile=nstemplate):
    """ NSupdate your Zone """

    # Get the NS secure keys
    myns_keys = load_mycnf()
    keyname = myns_keys["keyname"]
    key = myns_keys["key"]
    rndckey = keyname + ':' + key

    cmd = "%s -y '%s' -v %s > /dev/null 2>&1" % (nsupdate, rndckey, nfile)

    try:
        if syscall(cmd):
           logger.info("Successfully updated '%s' zone" % zone)
	   os.remove(nfile)   # delete the tempfile
        else:
           raise
    except Exception, ex:
        logger.error("While nsupdate to '%s' zone" % zone)
        sys.exit(1)

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
        logger.error("Fetching result - no '%s' zone available, please provide correct zone name" % zone)
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
        return 0
    except Exception, ex:
        logger.error("While updating database")
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
                 logger.error("'%s' record for '%s' with similar content '%s' already found in zone db, please check and try again!" % (type, name, content))
                 sys.exit(1)
              else:
                 logger.warning("'%s' record for '%s' with different content '%s' already found in zone db." % (type, name, contentm))
    except Exception, ex:
        return 0
    else:
        return 0

# ++ =================================================================================== ++
# Git for BindAdmin
# ++ =================================================================================== ++

def gitInit(zonepath):
    """ Validate git enabled for zonepath """

    git_dir = os.path.join(zonepath, '.git')
    if not os.path.isdir(git_dir):
       logger.error("git not initialized in '%s'" % zonepath)
       sys.exit(1)

def gitAdd(zone, zonepath):
    try:
        cmd = ['git', 'add', zone]
        p = subprocess.Popen(cmd, cwd=zonepath)
        p.wait()
        return True
    except Exception, ex:
        logger.error("While added to git")
        sys.exit(1)

def gitCommit(message, zonepath):
    try:
        cmd = ['git', 'commit', '-m', message]
        p = subprocess.Popen(cmd, cwd=zonepath, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.wait()
        return True
    except Exception, ex:
        logger.error("While Commit to git")
        sys.exit(1)

def gitReset(zonepath):
    try:
        cmd = ['git', 'reset', 'HEAD', '--hard']
        p = subprocess.Popen(cmd, cwd=zonepath, stdout=subprocess.PIPE)
        p.wait()
        return True
    except Exception, ex:
        logger.error("While git reset to HEAD")
        sys.exit(1)

def gitClean(zonepath):
    try:
        cmd = ['git', 'clean', '-f']
        p = subprocess.Popen(cmd, cwd=zonepath)
        p.wait()
        return True
    except Exception, ex:
        logger.error("While git clean untracked files")
        sys.exit(1)

def gitPull(zonepath):
    try:
        cmd = ['git', 'pull', 'origin', 'master']
        p = subprocess.Popen(cmd, cwd=zonepath)
        p.wait()
        return True
    except Exception, ex:
        logger.error("While git pull origin master")
        sys.exit(1)

def gitPush(zonepath):
    try:
        cmd = ['git', 'push', '-u', 'origin', 'HEAD']
        p = subprocess.Popen(cmd, cwd=zonepath)
        p.wait()
        return True
    except Exception, ex:
        logger.error("While git push to upstream")
        sys.exit(1)

def gitHEAD(zonepath):
    try:
        cmd = ['git', 'log', '--oneline', '-1']
        p = subprocess.Popen(cmd, cwd=zonepath, stdout=subprocess.PIPE)
        p.wait()
        return p.stdout.read().strip()
    except Exception, ex:
        logger.error("While looking for latest git commit")
        sys.exit(1)
