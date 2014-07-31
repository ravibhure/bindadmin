# BindAdmin, bind zone manager

### bindadmin is demand to manage bind zones, which can be stored in mysql database and called to build zone file when required, at the same time it should be able to add/update/delete and record type and maintain the logging activity.

          1)    We provide
            Type=A,CNAME
            Zonefile=example,com
            Domain=www
            IP/Alias/value=value

          2)    Write to DB
          3)    Fetch the all data sets for the zonefile
          4)    Generate the zone file using jinja template
          5)    Sanity checks and Verify zone
          6)    rndc reloads dynamic
          7)    git commit and push
          8)    rndc freeze (not to update)


### Usages

      [root@localhost bindadmin]# ./bindmanager.py
      usage: bindmanager.py [-h] {add,delete,show} ...
      bindmanager.py: error: too few arguments

      [root@localhost bindadmin]# ./bindmanager.py  add -h
      usage: bindmanager.py add [-h] -n NAME -t TYPE -c CONTENT [-tl TTL] -z ZONE

      optional arguments:
        -h, --help            show this help message and exit
        -n NAME, --name NAME  The record name to add
        -t TYPE, --type TYPE  The record type to add for record name
        -c CONTENT, --content CONTENT
                              The record value to add for record name
        -tl TTL, --ttl TTL    The record ttl to add for record name
        -z ZONE, --zone ZONE  Set the zone to be updated

      [root@localhost bindadmin]# ./bindmanager.py  delete -h
      usage: bindmanager.py delete [-h] -n NAME -t TYPE [-c CONTENT] -z ZONE

      optional arguments:
        -h, --help            show this help message and exit
        -n NAME, --name NAME  The record name to delete
        -t TYPE, --type TYPE  The record type to delete for record name
        -c CONTENT, --content CONTENT
                              The record value to add for record name
        -z ZONE, --zone ZONE  Set the zone to be updated

      [root@localhost bindadmin]# ./bindmanager.py  show -h
      usage: bindmanager.py show [-h] -z ZONE [-n NAME] [-c CONTENT]

      optional arguments:
        -h, --help            show this help message and exit
        -z ZONE, --zone ZONE  Set the zone to be check
        -n NAME, --name NAME  The record name to be check
        -c CONTENT, --content CONTENT
                              The record value or ip address to be check


### TODO

      If adding 'A' record type for any already exists 'name', check if there is already any entry for 'name' with any other 'A' record, if found
      print "WARNING: '%s' record for '%s', already found with different content value!" % (type, name, content)

      If adding 'CNAME' record, validate the CNAME 'content' record is present with 'A' record, if not exit with message.
      print "ERROR: '%s' record for '%s', doesn't have any 'A' record value!" % (type, name)

      Validate given 'name', which can be accepted with FQDN (with zone) or simple HOSTNAME
      (we need to add .zone.com after hostname if not found)

