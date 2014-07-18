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

