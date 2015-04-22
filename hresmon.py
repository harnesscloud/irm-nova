#!/usr/bin/env python
# Description
# This is the monitoring deamon that interacts with DB to write the monitored data per VM, and removes them once finished. It exposes methods to create VM table after a VM is created,
# create reports on the VM resource usage, and delete the table once the VM is destroyed.
#
# Each time a vm is created a new entry is added to the main table (resources-status) with active flag true,  a new thread
# associated to this table is created. The thread starts to read resource usage values and write them in the table. When the VM has ended is lifecyle, the irm-nova will request the stats
# for that VM. This will start a dedicated thread to analyse calculate the stats from the table
#
# 
#
# Status
# - functions to be implemented
#
#
#

import optparse, json, thread, ConfigParser, os, sqlite3, subprocess, time
from threading import Thread
import logging
import logging.handlers as handlers
from libnova import *
import hresmonAgent
from daemon import *


# This function is exposed to the IRM-NOVA which adds entry whenever a VM needs to be monitored. Essentially is creating a new request to hresmon
def addResourceStatus(uuid,host,status):
    print "In addResourceStatus",uuid,host,status
    db = sqlite3.connect("hresmon.sqlite")
    db.execute('''INSERT INTO resources(uuid,HOST,status) VALUES (?,?,?)''',[uuid,host,status])
    db.commit()
    db.close

def updateResourceStatus ():
    print "In updateResourceStatus"

def deleteResourceStatus():
    print "In deleteResourceStatus"

# this function creates an agent python file to a local or remote host and starts the agent
def createAgent():
    print "In createAgent"
    agent = hresmonAgent.Agent()
    agent.run(5,"b86782bd-54a3-48d8-b48d-651e53637161")

def destroyAgent():
    print "In destroyAgent"
    time.sleep(20)
    hresmonAgent.stop()

def destroyAllAgents():
    print "In destroyAllAgents"

def getResourceValueStoreStats():
    print "In getResourceValueStoreStats"

def createStatsListener():
    print "In createStatsListener"

def destroyStatsListener():
    print "In destroyStatsListener"

def checkNewRequests():
    print "In checkNewRequests"
    db = sqlite3.connect("hresmon.sqlite")
    cursor = db.cursor()
    cursor.execute('''SELECT * from resources WHERE status = "NEW"''')
    all_rows = cursor.fetchall()
    for row in all_rows:
        print row

    db.close

# if there is not a DB one will be created with the resource-status table
def init():
    conn = sqlite3.connect("hresmon.sqlite")
    conn.execute('''CREATE TABLE IF NOT EXISTS resources ("uuid" TEXT PRIMARY KEY  NOT NULL  UNIQUE , "HOST" TEXT DEFAULT False, "status" BOOL NOT NULL  DEFAULT False)''')
    conn.close()


# the daemon starts and checks the resources-status table constantly for new requests for monitoring by checking if the Status is NEW. If so, it calls the createAgent function and call updateResourceStatus to update the resource-status table relative entry with the name of the agent created and status to ACTIVE
def start():
    print "In start"
    # check if irm already running
    myname = os.path.basename(__file__)
    command = "ps -fe | grep "+myname+" | grep python | grep -v grep"
    proccount = subprocess.check_output(command,shell=True).count('\n')
    proc = subprocess.check_output(command,shell=True)
    if proccount > 1:
        print "---Check if irm is already running. Connection error---"
        sys.exit(0)
    else:
        print"hresmon started"
        addResourceStatus(createRandomID(10),"openstack-compute3.dhcp.bfsl.sap.corp","NEW")
        checkNewRequests()

    #return IP_ADDR

def main():
    init()
    start()
    createAgent()
    destroyAgent()

if __name__ == '__main__':
    main()