# BindAdmin, bind zone manager

#### bindadmin is demand to manage bind zones, which can be stored in mysql database and called to build zone file when required, at the same time it should be able to add/update/delete and record type and maintain the logging activity.

          1)	We provide
            Type=A,CNAME
            Zonefile=example,com
            Domain=www
            IP/Alias/value=value

          2)	Write to DB
          3)	Fetch the all data sets for the zonefile
          4)	Generate the zone file using jinja template
          5)	Sanity checks and Verify zone
          6)	rndc reloads dynamic
          7)	git commit and push
          8)	rndc freeze (not to update)

### Installation

#### Setup database

      mysqladmin create dnsdb
      mysql -Bse "create user 'dnsdb'@'localhost' identified by 'password'"
      mysql -Bse "grant all privileges on dnsdb.* to 'dnsdb'@'localhost'"

### Usages

      [root@ggvaapp07vm2 bindadmin]# ./bindmanager.py
      usage: bindmanager.py [-h] {add,delete,show} ...
      bindmanager.py: error: too few arguments

      [root@ggvaapp07 bindadmin]# ./bindmanager.py -h
      usage: bindmanager.py [-h] {add,delete,show} ...

      Queries the zone database for Build information

      positional arguments:
        {add,delete,show}
          show             shows your defined search from given zone
          add              Add the given record to the zone
          delete           Remove the given record from the zone(s)

      optional arguments:
        -h, --help         show this help message and exit

      To know more, write to: ravibhure@gmail.com

      [root@ggvaapp07 bindadmin]# ./bindmanager.py show -h
      usage: bindmanager.py show [-h] -z ZONE [-n NAME] [-c CONTENT] [-l]

      optional arguments:
        -h, --help            show this help message and exit
        -z ZONE, --zone ZONE  Set the zone to be check
        -n NAME, --name NAME  The record name to be check
        -c CONTENT, --content CONTENT
                              The record value or ip address to be check
        -l, --list            List all record values for specified zone


      [root@ggvaapp07 bindadmin]# ./bindmanager.py add -h
      usage: bindmanager.py add [-h] -n NAME -t TYPE -c CONTENT [-tl TTL] -z ZONE

      optional arguments:
        -h, --help            show this help message and exit
        -n NAME, --name NAME  The record name to add
        -t TYPE, --type TYPE  The record type to add for record name
        -c CONTENT, --content CONTENT
                              The record value to add for record name
        -tl TTL, --ttl TTL    The record ttl to add for record name
        -z ZONE, --zone ZONE  Set the zone to be updated


      [root@ggvaapp07 bindadmin]# ./bindmanager.py delete -h
      usage: bindmanager.py delete [-h] -n NAME -t TYPE [-c CONTENT] -z ZONE

      optional arguments:
        -h, --help            show this help message and exit
        -n NAME, --name NAME  The record name to delete
        -t TYPE, --type TYPE  The record type to delete for record name
        -c CONTENT, --content CONTENT
                              The record value to add for record name
        -z ZONE, --zone ZONE  Set the zone to be updated


### TODO:

      * Done - If adding 'A' record type for any already exists 'name', check if there is already any entry for 'name' with any other 'A' record, if found
      print "WARNING: '%s' record for '%s', already found with different content value!" % (type, name, content)

      If adding 'CNAME' record, validate the CNAME 'content' record is present with 'A' record, if not exit with message.
      print "WARNING: '%s' record for '%s', doesn't have any 'A' record value!" % (type, name)

      * Done -  Validate given 'name', which can be accepted with FQDN (with zone) or simple HOSTNAME
      (we need to add .zone.com after hostname if not found)

      If deleting 'A' record, check and remove if there are any 'CNAME' records with that 'A' records.

      Add activity event records to log file and to database.

      Find and List all broken records, those are not resolve from your zones/domains

      Replace record type 'A' to 'CNAME'
        Condition match found: If adding 'A' record, and the IP already assinged to another hostname, warn and ask to user
        > Do you want to add cname against the match found or continue
        If yes, add record to cname, if no go with what your wants
        add/delete (if it found any existing record set for that content)

      If deleting record 'anytype' (without giving -c content), if match result more than one,
        ask user to provide input Y/N , to delete entire match found.

      Search wildcard or nearest match while showing search result.

      Replace 'insert' with 'update' sql statement in zone2sql

      Add zone with base template

      Adding record type 'A' also adds the reverse PTR for ..
