#!/usr/bin/env python
# Description
# This is the monitoring deamon that interacts with DB to write the monitored data per instance (VM or container). It exposes methods to create instance table after a instance is created,
# create reports on the instance resource usage.
#
# Each time an instance is created a new entry is added to the main table (resources) with NEW in the status. A new thread
# associated to this table is created in the compute node. The thread starts to read resource usage values and write them in a local table. Raw data measurements can be requested through irm-nova api
# for each instance
#
# Status
# - all implemented
#
#
#

import optparse, json, thread, ConfigParser, os, sqlite3, subprocess, time, multiprocessing, requests, datetime
from threading import Thread
import logging
import logging.handlers as handlers
from libnova import *
#from daemon import *

global myname, myprocesses, hresmonDbName

hresmonDbName = "hresmon.sqlite"
myname = os.path.basename(__file__)
TIMEOUT = 4

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
    try:
        db = sqlite3.connect(hresmonDbName)
        db.execute('''INSERT INTO resources(uuid,HOST,REQUEST,status) VALUES (?,?,?,?)''',[uuid,host,request,status])
        db.commit()
        db.close
    except sqlite3.Error, e:
        error = {"message":e,"code":500}
        logger.error(error)
        return error

def updateResourceStatus (uuid,status):
    print "In updateResourceStatus"
    try:
        db = sqlite3.connect(hresmonDbName)
        cur = db.cursor()
        cur.execute('''UPDATE resources SET status= :status WHERE uuid= :uuid''',{'status':status,'uuid':uuid})
        db.commit()
        db.close
    except sqlite3.Error, e:
        error = {"message":e,"code":500}
        logger.error(error)
        return error

# This function is exposed to the IRM-NOVA to check if the status of a monitoring instance
def checkResourceStatus(uuid):
    print "In checkResourceStatus",uuid
    try:
        db = sqlite3.connect(hresmonDbName)
        cur = db.cursor()
        query = "SELECT status FROM resources WHERE uuid = \'"+uuid+"\'"
        cur.execute(query)
        [status] = cur.fetchone()
        db.close
    except TypeError, e:
        warning = {"message":e,"code":"500"}
        print warning
        logger.warning(warning)
        return warning
    except sqlite3.Error, e:
        error = {"message":e,"code":500}
        logger.error(error)
        return error

    logger.info("Completed!")
    return status

def deleteResourceStatus():
    print "In deleteResourceStatus"

# this function creates an agent python file to a local or remote host and starts the agent
def createAgent(data,url):
    print "In createAgent"
    #print "url",url
    logger.info("Called")
    headers = {'content-type': 'application/json'}
    try:
        #print "url",url
        r = requests.post('http://'+url+':12000/createAgent', data, headers=headers)

        logger.info("response:"+json.dumps(r.json()))
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        logger.error(error)
        return error
    except requests.exceptions.RequestException:
        error = {"message":"socket error","code":"500"}
        print error
        logger.error(error)
        return error

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
            print r
            logger.warning(r)
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        logger.error(error)
        return error
    except requests.exceptions.RequestException:
        error = {"message":"RequestException","code":"500"}
        print error
        logger.error(error)
        return error

    logger.info("Completed!")
    return r

def getUrlbyUuid(uuid):
    logger.info("Called")
    print "In getUrlbyUuid"
    ip = ""
    try:
        db = sqlite3.connect(hresmonDbName)
        cur = db.cursor()
        query = "SELECT HOST FROM resources WHERE uuid = \'"+uuid+"\'"
        cur.execute(query)
        [ip] = cur.fetchone()
        db.close
        logger.info("Completed!")
    except TypeError, e:
        warning = {"message":e,"code":"500"}
        print warning
        logger.warning(warning)
        return ""
    except sqlite3.Error, e:
        error = {"message":e,"code":500}
        logger.error(error)
        return error

    return ip

def getResourceValueStore(req):
    print "In getResourceValueStore"
    logger.info("Called")
    headers = {'content-type': 'application/json'}
    result = {}
    try:
        url = getUrlbyUuid(req['ReservationID'])
        jsondata = json.dumps(req)
        r = requests.post('http://'+url+':12000/getResourceValueStore', data=jsondata, headers=headers)
        result["Metrics"] = r.json()
        #logger.info("response:"+json.dumps(result))
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        logger.error(error)
        return error
    except Exception,e:
        error = {"message":e,"code":"500"}
        logger.error(error)
        return error
    except TypeError,e:
        error = {"message":e,"code":"500"}
        logger.error(error)
        return error
    logger.info("Completed!")
    return result

def checkNewRequests():
    print "In checkNewRequests"
    while True:
        try:
            db = sqlite3.connect(hresmonDbName)
            cursor = db.cursor()
            cursor.execute('''SELECT * from resources WHERE status = "NEW"''')
            all_rows = cursor.fetchall()
            #print "all_rows",all_rows
            for row in all_rows:
                #print "timestamp",row[4]
                now = datetime.datetime.now()
                #print "now",now
                then = datetime.datetime.strptime(row[4],"%Y-%m-%d %H:%M:%S")
                tdelta = now - then
                seconds = tdelta.total_seconds()
                #print "tdelta",seconds
                if seconds < TIMEOUT:
                    r = createAgent(row[2],row[1])
                    res = r.json()
                    if 'code' not in res:
                        updateResourceStatus(row[0],"RUNNING")
                else:
                    updateResourceStatus(row[0],"ERROR")

                #time.sleep(5)
            db.close
            time.sleep(0.5)
        except AttributeError,e:
            error = {"message":e,"code":"400"}
            print error
            logger.error(error)
            #return error
        except sqlite3.Error, e:
            print e
            error = {"message":e,"code":500}
            logger.error(error)
            #return error

# if there is not a DB one will be created with the resource-status table
def init():
    createLogger()
    try:
        conn = sqlite3.connect(hresmonDbName)
        conn.execute('''CREATE TABLE IF NOT EXISTS resources ("uuid" TEXT PRIMARY KEY  NOT NULL  UNIQUE , "HOST" TEXT DEFAULT False, "REQUEST" TEXT NOT NULL, "status" BOOL NOT NULL  DEFAULT False, "Timestamp" DATE DEFAULT (datetime('now','localtime')))''')
        conn.close()
    except sqlite3.Error, e:
        error = {"message":e,"code":500}
        logger.error(error)
        return error


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
        t = multiprocessing.Process(name="monMaster",target=checkNewRequests,args=())
        t.daemon = True
        t.start()
        msg = "hresmon started"
        print msg
        while True:
           time.sleep(100)


def main():
    init()
    start()

if __name__ == '__main__':
    main()
