#!/usr/bin/env python
# Description
# This is the monitoring agent that is used to collect resource usage information for a specific VM. For each new VM, this agent is copied over to a host and started.
# A local DB is then created with a resourceValuesStore table. When the VM has ended is lifecyle, the irm-nova will request the stats
# for that VM. This will start a dedicated thread to analyse calculate the stats from the table
#
# 
#
# Status
# - functions to be implemented
#
#
#

import optparse, json, os
import sqlite3, subprocess, time, sys
import threading
import multiprocessing
from bottle import route, run,response,request,re

import logging
import logging.handlers as handlers

# This variable can assume values: RUNNING, NOTRUNNING
#global STATUS
#STATUS = "NOTRUNNING"

global myname, myprocesses
myname = os.path.basename(__file__)

logger = logging.getLogger("Rotating Log")
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter(fmt='%(asctime)s.%(msecs)d - %(levelname)s: %(filename)s - %(funcName)s: %(message)s', datefmt='%d/%m/%Y %H:%M:%S')
handler = handlers.TimedRotatingFileHandler(os.path.splitext(myname)[0]+".log",when="H",interval=24,backupCount=0)
## Logging format
handler.setFormatter(formatter)
logger.addHandler(handler)

# this will be moved in the agent code
def createResourceValuesStore(uuid):
    db = sqlite3.connect("hresmon.sqlite")
    db.execute('''CREATE TABLE IF NOT EXISTS \"resourceValuesStore_'''+uuid+'''\" ("CPU" FLOAT, "MEM" FLOAT, "TIMESTAMP" FLOAT)''')
    db.commit()
    db.close

# this will be moved in the agent code
def updateResourceValuesStore(uuid,cpu,mem,timestamp):
    #print "In updateResourceValuesStore"
    db = sqlite3.connect("hresmon.sqlite")
    tbname = "resourceValuesStore_"+uuid
    db.execute('''INSERT INTO \"'''+tbname+'''\"(CPU,MEM,TIMESTAMP) VALUES (?,?,?)''',[cpu,mem,timestamp])
    db.commit()
    db.close

# this will be moved in the agent code
def deleteResourceValuesStore():
    print "In deleteResourceValuesStore"

# this function creates an agent python file to a local or remote host and starts the agent
@route('/createAgent/', method='POST')
@route('/createAgent', method='POST')
def createAgent():
    logger.info("Called")
    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'POST, HEAD')
    #print "multiprocessing.active_children()", multiprocessing.active_children()
    try:          
        # get the body request
        try:
           req = json.load(request.body)
        except ValueError:
           print "Attempting to load a non-existent payload, please enter desired layout\n"
           logger.error("Payload was empty or incorrect. A payload must be present and correct")

        uuid = req['uuid']
        pollTime = float(req['pollTime'])
        if getProcessByName(uuid):
            action = "Agent already existing"
        else:
            print "CreateAgent request", uuid,pollTime
            t = multiprocessing.Process(name=uuid,target=runAgent, args=(pollTime,uuid))
            t.daemon = True
            t.start()
            action = "Agent created"

    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        return error
        logger.error(error)   
    logger.info("Completed!")
    
    result = {"Agent":uuid,"Action":action}

    jsondata = json.dumps(result)

    return jsondata

@route('/destroyAgent/', method='DELETE')
@route('/destroyAgent', method='DELETE')
def destroyAgent():
    logger.info("Called")
    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'POST, HEAD')
    try:          
        # get the body request
        try:
           req = json.load(request.body)
        except ValueError:
           print "Attempting to load a non-existent payload, please enter desired layout\n"
           logger.error("Payload was empty or incorrect. A payload must be present and correct")

        uuid = req['uuid']
        print "Destroy Agent request", uuid
        t = getProcessByName(uuid)
        t.terminate()

    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        return error
        logger.error(error)   
    logger.info("Completed!")
    
    result = {"Agent":uuid,"Action":"Destroyed"}

    jsondata = json.dumps(result)
    return jsondata

def getProcessByName(uuid):
    logger.info("Called")
    try:
        myprocesses = multiprocessing.active_children()

        for p in myprocesses:
            if p.name == uuid:
                return p
    except Exception.message, e:
        return e

def destroyAllAgents():
    print "In destroyAllAgents"

def getResourceValueStoreStats():
    print "In getResourceValueStoreStats"
    
def runAgent(pollTime,uuid):
    createResourceValuesStore(uuid)
    p = multiprocessing.current_process()
    getPid = "ps -fe | grep "+uuid+" | grep -v grep | awk '{print $2}'"
    pid = subprocess.check_output(getPid, shell=True).rstrip()
    print 'Starting', p.name, "to monitor",pid
    sys.stdout.flush()
    nproc = subprocess.check_output("nproc", shell=True).rstrip()

    while True:
        getValues = "top -b -p "+pid+" -n 1 | tail -n 1 | awk '{print $9, $10, strftime(\"%s\")}'"
        values = subprocess.check_output(getValues, shell=True).rstrip()
        values_decoded = values.decode('utf-8')
        [cpu, mem, timestamp] = values_decoded.split(' ', len(values_decoded))
        updateResourceValuesStore(uuid,float(cpu)/float(nproc),float(mem),float(timestamp))
        time.sleep(pollTime)
    
def getifip(ifn):
    '''
Provided network interface returns IP adress to bind on
'''
    import socket, fcntl, struct
    sck = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(sck.fileno(), 0x8915, struct.pack('256s', ifn[:15]))[20:24])

def startAPI(IP_ADDR,PORT_ADDR):
    # check if hresmonAgent already running
    command = "ps -fe | grep "+myname+" | grep python | grep -v grep"
    proccount = subprocess.check_output(command,shell=True).count('\n')
    proc = subprocess.check_output(command,shell=True)
    if proccount > 1:
        print "---Check if hresmonAgent is already running. Connection error---"
        sys.exit(0)
    else:
        print"hresmonAgent API IP address:",IP_ADDR
        API_HOST=run(host=IP_ADDR, port=PORT_ADDR)
    return IP_ADDR


# if there is not a DB one will be created with the resource-status table
def init(interface):
    global IP_ADDR
    if interface != "":
        IP_ADDR=getifip(interface)
    else:
        IP_ADDR="0.0.0.0"
    
def main():
    usage = "Usage: %prog [option] arg"
    #paragraph of help text to print after option help
    epilog= "Copyright 2015 SAP Ltd"
    #A paragraph of text giving a brief overview of your program
    description="""hresmonAgent is the agent used by the hresmon to monitor resource usage of VMs in compute nodes"""
    parser = optparse.OptionParser(usage=usage,epilog=epilog,description=description)
    
    parser.add_option('-v','--version', action='store_true', default=False,dest='version',help='show version information')
    #parser.add_option('-h','--help', action='store_true', default=False,dest='help',help='show help')
    parser.add_option('-i','--interface', action='store', type="string", default=False,dest='interface',help='network interface to start the API')
    parser.add_option('-p','--port', action='store', default=False,dest='port',help='port to start the API')

    options, args = parser.parse_args()
    #print options, args
    if options.version:
        #noExtraOptions(options, "version")
        VERSION = "0.1"
        #os.system("clear")
        text = '''
Copyright 2014-2015 SAP Ltd
'''
        print VERSION
        sys.exit(1)
    
    global PORT_ADDR 
    if options.interface:
        INTERFACE = options.interface 
    else:
        INTERFACE = "eth0"
        print "No interface specified, using "+INTERFACE+" as default"
    
    if options.port:
        PORT_ADDR = options.port
    else:
        PORT_ADDR = 12000
        print "No port specified, using "+str(PORT_ADDR)+" as default"

    try:
       init(INTERFACE)
       print "Initialization done"
       startAPI(IP_ADDR,PORT_ADDR)
    except Exception, e:
       e = sys.exc_info()[1]
       print "Error",e

def noExtraOptions(options, *arg):
    options = vars(options)
    for optionValue in options.values():
        print optionValue
        if not (optionValue == False):
            print "Bad option combination"
            sys.exit()


if __name__ == '__main__':
    main()