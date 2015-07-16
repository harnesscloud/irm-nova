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
#from daemon import *

global myname, myprocesses
myname = os.path.basename(__file__)

def createLogger():
    global logger
    logger = logging.getLogger("Rotating Log")
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(fmt='%(asctime)s.%(msecs)d - %(levelname)s: %(filename)s - %(funcName)s: %(message)s', datefmt='%d/%m/%Y %H:%M:%S')
    handler = handlers.TimedRotatingFileHandler(os.path.splitext(myname)[0]+".log",when="H",interval=24,backupCount=0)
    ## Logging format
    handler.setFormatter(formatter)
    if not logger.handlers:
        logger.addHandler(handler)

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
    #print "url",url
    logger.info("Called")
    headers = {'content-type': 'application/json'}
    try:
        r = requests.post('http://'+url+':12000/createAgent', data, headers=headers)
        #print "url",url
        logger.info("response:"+json.dumps(r.json()))
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        return error
        logger.error(error)
    except requests.exceptions.RequestException:
        error = {"message":"socket error","code":"500"}
        print error
        return error
        logger.error(error)

    logger.info("Completed!")
    return r

def destroyAgent(uuid):
    logger.info("Called")
    print "In destroyAgent"
    headers = {'content-type': 'application/json'}
    try:
        url = getUrlbyUuid(uuid)
        if url != "":
            data = {"uuid":uuid}
            jsondata = json.dumps(data)
            #print jsondata
            #print "url",url
            r = requests.delete('http://'+url+':12000/terminateAgent', data=jsondata, headers=headers)
            updateResourceStatus (uuid,"ENDED")
            logger.info("response:"+json.dumps(r.json()))
        else:
            r = "No Agent for",uuid
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        return error
        logger.error(error)
    except requests.exceptions.RequestException:
        error = {"message":"RequestException","code":"500"}
        print error
        return error
        logger.error(error)

    logger.info("Completed!")
    return r

def getUrlbyUuid(uuid):
    logger.info("Called")
    print "In getUrlbyUuid"
    ip = ""
    db = sqlite3.connect("hresmon.sqlite")
    cur = db.cursor()
    query = "SELECT HOST FROM resources WHERE uuid = \'"+uuid+"\'"
    cur.execute(query)
    try:
        [ip] = cur.fetchone()
        logger.info("Completed!")
    except TypeError, e:
        error = {"message":e,"code":"500"}
        print error
        logger.error(error)
    return ip

def destroyAllAgents():
    print "In destroyAllAgents"

def getResourceValueStore(req):
    print "In getResourceValueStore"
    logger.info("Called")
    headers = {'content-type': 'application/json'}
    result = {}
    try:
        #for uuid in req['ReservationID']:
        #uuid = req['ReservationID']
        #print "UUID",uuid
        url = getUrlbyUuid(req['ReservationID'])
        #request = {"uuid":req['ReservationID'],"Entry":req['Entry']}
        #if derivedMetrics:
        #    request['derived'] = derivedMetrics
        jsondata = json.dumps(req)
        #print "JSONDATA",jsondata
        r = requests.post('http://'+url+':12000/getResourceValueStore', data=jsondata, headers=headers)
        #print r.json()
        #updateResourceStatus (uuid,"REPORTED")
        #result[uuid] = r.json()
        result["Metrics"] = r.json()
        logger.info("response:"+json.dumps(result))
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        return error
        logger.error(error)
    except Exception,e:
        error = {"message":e,"code":"500"}
        return error
        logger.error(error)
    except TypeError,e:
        error = {"message":e,"code":"500"}
        return error
        logger.error(error)
    logger.info("Completed!")
    return result

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
            try:
                r = createAgent(row[2],row[1])
                res = r.json()
                print res
                if 'code' not in res:
                    updateResourceStatus(row[0],"RUNNING")
            except AttributeError,e:
                error = {"message":e,"code":"444"}
                print error
                return error
                logger.error(error)
            
            time.sleep(5)

    db.close

# if there is not a DB one will be created with the resource-status table
def init():
    createLogger()
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
        error = "---Check if "+myname+" is already running. Connection error---"
        print error
        logger.error(error)
        sys.exit(0)
    else:
        print"hresmon started"
        #with open ("testJsonAgentRequest", "r") as myfile:
        #    data=myfile.read()
        
        #addResourceStatus(createRandomID(10),"10.55.164.160", data, "NEW")
        
        t = multiprocessing.Process(name="monMaster",target=checkNewRequests,args=())
        t.daemon = True
        t.start()
        msg = "hresmon started"
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