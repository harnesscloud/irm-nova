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

import optparse, json, thread, ConfigParser, os, sqlite3, subprocess, time, multiprocessing, requests
from threading import Thread
import logging
import logging.handlers as handlers
from libnova import *
import hresmonAgent
from daemon import *


# This function is exposed to the IRM-NOVA which adds entry whenever a VM needs to be monitored. Essentially is creating a new request to hresmon
def addResourceStatus(uuid,host,request,status):
    print "In addResourceStatus",uuid,host,status
    db = sqlite3.connect("hresmon.sqlite")
    db.execute('''INSERT INTO resources(uuid,HOST,REQUEST,status) VALUES (?,?,?,?)''',[uuid,host,request,status])
    db.commit()
    db.close

def updateResourceStatus (uuid,status):
    print "In updateResourceStatus"
    db = sqlite3.connect("hresmon.sqlite")
    cur = db.cursor()
    cur.execute('''UPDATE resources SET status= :status WHERE uuid= :uuid''',{'status':status,'uuid':uuid})
    db.commit()
    db.close

def deleteResourceStatus():
    print "In deleteResourceStatus"

# this function creates an agent python file to a local or remote host and starts the agent
def createAgent(data,url):
    print "In createAgent"
    #logger.info("Called")
    headers = {'content-type': 'application/json'}
    try:
        r = requests.post('http://'+url+':12000/createAgent', data, headers=headers)
        print r
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        return error
        #logger.error(error)
    #logger.info("Completed!")
    return r

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
    while True:
        cursor.execute('''SELECT * from resources WHERE status = "NEW"''')
        all_rows = cursor.fetchall()
        for row in all_rows:
            print row[0],row[3]
            createAgent(row[2],row[1])
            updateResourceStatus(row[0],"RUNNING")
        time.sleep(10)

    db.close

# if there is not a DB one will be created with the resource-status table
def init():
    conn = sqlite3.connect("hresmon.sqlite")
    conn.execute('''CREATE TABLE IF NOT EXISTS resources ("uuid" TEXT PRIMARY KEY  NOT NULL  UNIQUE , "HOST" TEXT DEFAULT False, "REQUEST" TEXT NOT NULL, "status" BOOL NOT NULL  DEFAULT False)''')
    conn.close()


# the daemon starts and checks the resources-status table constantly for new requests for monitoring by checking if the Status is NEW. If so, it calls the createAgent function and call updateResourceStatus to update the resource-status table relative entry with the name of the agent created and status to ACTIVE
def start():
    print "In start"
    # check if it's already running
    myname = os.path.basename(__file__)
    command = "ps -fe | grep "+myname+" | grep python | grep -v grep"
    proccount = subprocess.check_output(command,shell=True).count('\n')
    proc = subprocess.check_output(command,shell=True)
    if proccount > 1:
        print "---Check if "+myname+" is already running. Connection error---"
        sys.exit(0)
    else:
        print"hresmon started"
        with open ("testJsonAgentRequest", "r") as myfile:
            data=myfile.read()
        
        addResourceStatus(createRandomID(10),"10.55.164.160", data, "NEW")
        
        t = multiprocessing.Process(name="monMaster",target=checkNewRequests,args=())
        t.daemon = True
        t.start()
        msg = "Agent created"
        print msg
        while True:
            pass
        


def main():
    init()
    start()
    #createAgent()
    #destroyAgent()

if __name__ == '__main__':
    main()