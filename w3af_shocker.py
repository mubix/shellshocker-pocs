#!/usr/bin/python

import os, sys
from time import sleep

if len(sys.argv) != 2:
        print "Usage: shell_shocker <URL>"
        sys.exit(0)

target=sys.argv[1]
# Creates a temporary w3af audit file
fname='w3af_'+target.split('/')[2]+".w3af"

f=open(fname, 'w')
# Audit file will enable web_spider, and plugin named "shell_shock"
# You may need to modify plugin names for your setup
f.write("plugins\n")
f.write("crawl web_spider\n")
f.write("audit shell_shock\n")
f.write("back\n")
f.write("\n")
f.write("target\n")
f.write("set target "+target+"\n")
f.write("back\n")
f.write("\n")
f.write("start")
f.close()

# Invoke w3af_console with audit script
os.system("w3af_console -s "+fname)
sleep(2)
# Remove audit script
os.system("rm "+fname)

