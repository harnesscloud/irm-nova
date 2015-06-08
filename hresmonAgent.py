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

global myname, myprocesses, commandTimestamp, MODE

# MODE can be MULTI or SINGLE. The former allows specify different poll time for each metric, 
# while the latter use the same poll time for all metrics
 
MODE = "MULTI"

commandTimestamp = "date +%s"
myname = os.path.basename(__file__)

logger = logging.getLogger("Rotating Log")
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter(fmt='%(asctime)s.%(msecs)d - %(levelname)s: %(filename)s - %(funcName)s: %(message)s', datefmt='%d/%m/%Y %H:%M:%S')
handler = handlers.TimedRotatingFileHandler(os.path.splitext(myname)[0]+".log",when="H",interval=24,backupCount=0)
## Logging format
handler.setFormatter(formatter)
logger.addHandler(handler)

def createResourceValuesStore(uuid,metrics):
    query = buildSqlCreateSingle(metrics,uuid)
    print query
    db = sqlite3.connect("hresmon.sqlite")
    cur = db.cursor()
    tbname = "resourceValuesStore_"+uuid
    cur.execute(query)
    db.commit()
    db.close
    logger.info("Created table "+tbname)

def createResourceValuesStoreMulti(uuid,metrics):
    db = sqlite3.connect("hresmon.sqlite")
    for m in metrics:
        #print m
        #if m['name'] != "TIMESTAMP":
        query = buildSqlCreateMulti(m,uuid)
        cur = db.cursor()
        tbname = "resourceValuesStore_"+m['name']+"_"+uuid
        cur.execute(query)
        db.commit()
        logger.info("Created table "+tbname)
    db.close

def updateResourceValuesStore(uuid,values):
    tbname = "resourceValuesStore_"+uuid
    query = buildSqlInsert(len(values),tbname)
    db = sqlite3.connect("hresmon.sqlite")
    cur = db.cursor()
    cur.execute(query,values)
    db.commit()
    db.close
    logger.info("Updating table "+tbname)

def updateResourceValuesStoreMulti(uuid,name,values):
    tbname = "resourceValuesStore_"+name+"_"+uuid
    query = buildSqlInsert(len(values),tbname)
    db = sqlite3.connect("hresmon.sqlite")
    cur = db.cursor()
    cur.execute(query,values)
    db.commit()
    db.close
    logger.info("Updating table "+tbname)

def buildSqlCreateSingle(metrics,uuid):
    tbname = "resourceValuesStore_"+uuid
    columns = ""
    for m in metrics:
        #print "In buildSqlCreate",m
        columns = columns+"\""+m['name']+"\" "+m['type']+","

    #columns = columns[:-1]
    columns = columns+" \"TIMESTAMP\" FLOAT"

    query = "CREATE TABLE IF NOT EXISTS \""+tbname+"\" ("+columns+")"
    return query

def buildSqlCreateMulti(metrics,uuid):
    tbname = "resourceValuesStore_"+metrics['name']+"_"+uuid
    columns = ""
    columns = columns+"\""+metrics['name']+"\" "+metrics['type']+", \"TIMESTAMP\" FLOAT"

    #columns = columns[:-1]

    query = "CREATE TABLE IF NOT EXISTS \""+tbname+"\" ("+columns+")"
    return query

def buildSqlInsert(nvalues,tbname):
    #tbname = "resourceValuesStore_"+uuid
    columns = ""
    for i in range(0,nvalues):
        columns = columns+"?,"

    columns = columns[:-1]

    query = "INSERT INTO \""+tbname+"\" VALUES ("+columns+")"
    #print query

    return query

def buildCommand(metrics):
    command = ""
    for m in metrics:
        command = command+m['command']+";"

    return command

# this will be moved in the agent code
def deleteResourceValuesStore():
    print "In deleteResourceValuesStore"

# this function creates an agent python file to a local or remote host and starts the agent
@route('/createAgent/', method='POST')
@route('/createAgent', method='POST')
def createAgent():
    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'POST, HEAD')
    #print "multiprocessing.active_children()", multiprocessing.active_children()
    try:          
        # get the body request
        try:
           req = json.load(request.body)
           #print req
        except Exception.message, e:
           print "Attempting to load a non-existent payload, please enter desired layout\n"
           logger.error("Payload was empty or incorrect. A payload must be present and correct")
           return error

        metrics = req['metrics']
        #command = req['command']
        uuid = req['uuid']
        pollTime = float(req['pollTime'])
        instanceType = req['instanceType']
        
        #print "metrics, command, uuid, pollTime",metrics,command,uuid,pollTime

        # check if the pid exists
        if instanceType == "container":
            pidCmd = "sudo docker ps | grep \""+uuid+" \" | awk '{ print $1 }'"
        elif instanceType == "vm":
            pidCmd = "ps -fe | grep \""+uuid+" \" | grep -v grep | awk '{print $2}'"
        
        pid = getPid(uuid,pidCmd) 
        if pid == "":
            msg = "No process existing for Agent "+uuid
            logger.error("No pid exists for process "+uuid)
            response.status = 404
            error = {"message":msg,"code":response.status}
            return error
        elif pid == "multiple":
            msg = "Multiple processes existing for Agent "+uuid
            logger.error("multiple pid exists for process "+uuid)
            response.status = 409
            error = {"message":msg,"code":response.status}
            return error
        else:
            # check if there is already an agent created
            if getProcessByName(uuid):
                msg = "Agent already existing "+uuid
                logger.error("Agent already exisits for process "+uuid)
                response.status = 409
                error = {"message":msg,"code":response.status}
                return error
            else:
                logger.info("CreateAgent request "+uuid+" "+str(pollTime))
                if MODE == "SINGLE":
                    t = multiprocessing.Process(name=uuid,target=runAgent, args=(pollTime,uuid,metrics,pid))
                elif MODE == "MULTI":
                    t = multiprocessing.Process(name=uuid,target=runAgentMulti, args=(pollTime,uuid,metrics,pid))
                
                t.daemon = True
                t.start()
                msg = "Agent created"

    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        return error
        logger.error(error)   
       
    result = {"Agent":uuid,"Message":msg}
    logger.info(result)
    jsondata = json.dumps(result)
    return jsondata

@route('/terminateAgent/', method='DELETE')
@route('/terminateAgent', method='DELETE')
def terminateAgent():
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
        print "Terminate Agent request", uuid
        t = getProcessByName(uuid)
        if t == None:
            msg = "No Agent found "+uuid
            logger.error("No Agent found "+uuid)
            response.status = 404
            error = {"message":msg,"code":response.status}
            return error
        else:
            logger.info("Terminate request "+uuid)
            t.terminate()
            msg = "Terminated"

    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        return error
        logger.error(error)
    
    result = {"Agent":uuid,"Message":msg}
    logger.info(result)
    jsondata = json.dumps(result)
    return jsondata

def getProcessByName(uuid):
    try:
        myprocesses = multiprocessing.active_children()

        for p in myprocesses:
            if p.name == uuid:
                return p
    except Exception.message, e:
        return e

def getPid(uuid,cmd):
    pid = subprocess.check_output(cmd, shell=True).rstrip()
    if "\n" in pid:
        #pid = pid.replace('\n',' ')
        pid = "multiple"
    return pid

def destroyAllAgents():
    print "In destroyAllAgents"

@route('/getResourceValueStore/', method='POST')
@route('/getResourceValueStore', method='POST')
def getResourceValueStore():
    logger.info("Called")
    print "In getResourceValueStore"

    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'POST, HEAD')

    try:
        try:
           req = json.load(request.body)
        except ValueError:
           print "Attempting to load a non-existent payload, please enter desired layout\n"
           logger.error("Payload was empty or incorrect. A payload must be present and correct")

        uuid = req['uuid']
        rformat = req['format']
        print "getResourceValueStore request", uuid

        tbname = "resourceValuesStore_"+uuid
        
        
        db = sqlite3.connect("hresmon.sqlite")
        cur = db.cursor()

        cur.execute('PRAGMA TABLE_INFO({})'.format("\""+tbname+"\""))

        # collect names in a list
        #names = [tup[1] for tup in cur.fetchall()]
        #print(names)
        tbheader = ""
        for tup in cur.fetchall():
            tbheader = tbheader + tup[1] +" "
        
        if rformat == "file":
            location = "/tmp/"
            tbfile = open(location+tbname, "wb")
            tbfile.write(tbheader+"\n")

        if rformat == "data":
            tbs = tbheader+"\n"

        cur.execute('select * from \"'+tbname+'\"')
        tb = cur.fetchall()
        for row in tb:
            #print row
            values = ""
            for v in range(0,len(row)):
                values = values+'{} '.format(row[v])
            #print values
            #values = values + "\n"
            if rformat == "file":
                tbfile.write(values+ "\n")
            if rformat == "data":
                tbs = tbs + values+ "\n"

        if rformat == "file":
            tbfile.close()
        
        db.close()
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        return error
        logger.error(error)

    if rformat == "file":
        result = {"Table exported":location+tbname}
    if rformat == "data":
        result = {"Table exported":tbs}
    logger.info(result)
    jsondata = json.dumps(result)
    return jsondata

@route('/getResourceValueStoreMulti/', method='POST')
@route('/getResourceValueStoreMulti', method='POST')
def getResourceValueStoreMulti():
    logger.info("Called")
    print "In getResourceValueStoreMulti"

    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'POST, HEAD')

    try:
        try:
           req = json.load(request.body)
        except ValueError:
           print "Attempting to load a non-existent payload, please enter desired layout\n"
           logger.error("Payload was empty or incorrect. A payload must be present and correct")

        uuid = req['uuid']
        rformat = req['format']
        nlines = req['lines']
        print "getResourceValueStore request", uuid

        #tbname = "resourceValuesStore_"+uuid
        
        
        db = sqlite3.connect("hresmon.sqlite")
        cur = db.cursor()

        sqlGetTablesByuuid = "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE \'%"+uuid+"%\';"

        #print sqlGetTablesByuuid

        cur.execute(sqlGetTablesByuuid)
        #tables = cur.fetchall()
        tables = [str(table[0]) for table in cur.fetchall()]
        #print tables

        # collect names in a list
        #names = [tup[1] for tup in cur.fetchall()]
        #print(names)
        matrix = {}
        files = []

        for tbname in tables:
            tbheader = ""
            tbs = ""
            #print "tbname",tbname
            #print "tbname.find('resourceValuesStore_')",tbname.find('resourceValuesStore_')
            #print "tbname.find('_'+uuid)",tbname.find('_'+uuid)
            METRIC = tbname[tbname.find('_')+1:tbname.find('_'+uuid)]

            cur.execute('PRAGMA TABLE_INFO({})'.format("\""+tbname+"\""))
            for tup in cur.fetchall():
                tbheader = tbheader + tup[1] +" "
                #print tup[1]
            
            if rformat == "file":
                location = "/tmp/"
                tbfile = open(location+tbname, "wb")
                tbfile.write(tbheader+"\n")
                files.append(location+tbname)

            #if rformat == "data":
            #    tbs = tbheader+"\n"

            if nlines == "all":
                cur.execute('select * from \"'+tbname+'\"')
            else:
                try:
                    nl = int(nlines)
                    cur.execute('select * from (select * from \"'+tbname+'\" ORDER BY TIMESTAMP DESC LIMIT '+nlines+') order by TIMESTAMP ASC')
                except ValueError:
                    response.status = 400
                    error = {"message":"ValueError: "+nlines,"code":response.status}
                    return error
                    logger.error(error)

            tb = cur.fetchall()
            for row in tb:
                #print row
                values = ""
                for v in range(0,len(row)):
                    values = values+'{} '.format(row[v])
                    #values = values+str(row[v])+" "
                    #print values
                #print values
                #values = values + "\n"
                if rformat == "file":
                    tbfile.write(values+ "\n")
                if rformat == "data":
                    tbs = tbs + values+ "\n"

            if rformat == "file":
                tbfile.close()

            #print tbs
            #matrix = matrix+"\""+str(METRIC)+"\""+":"+"\""+str(tbs)+"\""+",\n"
            matrix[str(METRIC)] = tbs
        
        db.close()
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        return error
        logger.error(error)
    
    #matrix = matrix[:-2]
    #print matrix
    if rformat == "file":
        result = {"Tables exported":files}
    if rformat == "data":
        result = matrix

    #print result
    logger.info(result)
    jsondata = json.dumps(result)
    return jsondata

    
def runAgent(pollTime,uuid,metrics,pid):
    createResourceValuesStore(uuid,metrics)
    p = multiprocessing.current_process()
    #pidCmd = "ps -fe | grep "+uuid+" | grep -v grep | awk '{print $2}'"
    #pid = getPid(uuid,pidCmd)
    msg = 'Starting '+p.name+ " to monitor "+pid
    print msg
    logger.info(msg)
    sys.stdout.flush()
    nproc = subprocess.check_output("nproc", shell=True).rstrip()
    command = buildCommand(metrics)+commandTimestamp
    if "__pid__" in command:
        command = command.replace("__pid__",pid)
    
    #print "New command", command

    while True:
        #getValues = "top -b -p "+pid+" -n 1 | tail -n 1 | awk '{print $9, $10, strftime(\"%s\")}'"
        values = subprocess.check_output(command, shell=True).rstrip()
        values_decoded = values.decode('utf-8')
        #print "values_decoded", values_decoded
        # This convert multiline to singleline
        values_decoded = values_decoded.replace("\n"," ")

        #print "length values_decoded",len(values_decoded.split(' ', len(values_decoded)))
        #nmetrics = len(values_decoded.split(' ', len(values_decoded)))
        #print nmetrics
        #for i in range(0,nmetrics):
        #    print metrics[i][0]

        #print "metrics",metrics
        values = values_decoded.split(' ', len(values_decoded))
        values[0] = float(values[0])/int(nproc)
        #print "values", values

        updateResourceValuesStore(uuid,values)
        time.sleep(pollTime)


def runAgentMulti(pollTime,uuid,metrics,pid):
    createResourceValuesStoreMulti(uuid,metrics)
    p = multiprocessing.current_process()
    msg = 'Starting '+p.name+ " to monitor "+pid
    print msg
    logger.info(msg)
    sys.stdout.flush()
    nproc = subprocess.check_output("nproc", shell=True).rstrip()
    #command = buildCommand(metrics)
    #print commandTimestamp
    
    pollMultiList = [int(m['pollMulti']) for m in metrics]
    #print "pollMultiList",pollMultiList

    while True:
        try:
            toBeMeasured = [x for x,y in enumerate(pollMultiList) if y == 1]
            #print toBeMeasured
        except ValueError:
            print "List does not contain value 1"
        #if some of the pollMulti has reached 1
        pollMultiList = [i - 1 for i in pollMultiList]

        if len(toBeMeasured) > 0:
            for i in toBeMeasured:
                command = metrics[i]['command']+";"+commandTimestamp
                if "__pid__" in command:
                    command = command.replace("__pid__",pid)

                values = subprocess.check_output(command, shell=True).rstrip()
                values_decoded = values.decode('utf-8')
                # This convert multiline to singleline
                values_decoded = values_decoded.replace("\n"," ")
                values = values_decoded.split(' ', len(values_decoded))
                #print "values", values
                name = metrics[i]['name']
                #print name
                if name == "CPU":
                    values[0] = float(values[0])/int(nproc)
                
                #print values
                updateResourceValuesStoreMulti(uuid,name,values)
                val = int(metrics[i]['pollMulti'])
                pollMultiList[i] = val
        
        #print toBeMeasured
        #print pollMultiList
        
        time.sleep(pollTime)

def runAgentC(pollTime,uuid,metrics):
    #createResourceValuesStore(uuid,metrics)
    p = multiprocessing.current_process()
    pidCmd = "sudo docker ps | grep "+uuid+" | awk '{ print $1 }'"
    pid = getPid(uuid,pidCmd)
    msg = 'Starting '+p.name+ " to monitor "+pid
    print msg
    logger.info(msg)
    sys.stdout.flush()
    nproc = subprocess.check_output("nproc", shell=True).rstrip()
    command = buildCommand(metrics)
    if "__pid__" in command:
        command = command.replace("__pid__",pid)
    
    print "New command", command
    
    cmd_timestamp = "date +%s"
    cmd_cpu_tot_time = "cat /proc/stat | grep \"^cpu \" | sed \"s:cpu  ::\" | awk '{ for(i=1;i<=NF;i++)SUM+=$i} END { print SUM }'"
    cmd_cpu_u_s_time = "cat /sys/fs/cgroup/cpuacct/docker/d7dd648037543d83d48570ed10d4cc25deebc3a89a24ba30bed94c3ae2bc17e3/cpuacct.stat | awk '{SUM+=$2} END { print SUM }'"
    cmd_mem_tot_byte = "cat /sys/fs/cgroup/memory/docker/d7dd648037543d83d48570ed10d4cc25deebc3a89a24ba30bed94c3ae2bc17e3/memory.limit_in_bytes"
    cmd_mem_u_s_byte = "cat /sys/fs/cgroup/memory/docker/d7dd648037543d83d48570ed10d4cc25deebc3a89a24ba30bed94c3ae2bc17e3/memory.usage_in_bytes"

    
    tot_time_cmd = "cat /proc/stat | grep \"^cpu \" | sed \"s:cpu  ::\" | awk '{ for(i=1;i<=NF;i++)SUM+=$i} END { print SUM, strftime(\"%s\") }'"
    u_s_time_cmd = "cat /sys/fs/cgroup/cpuacct/docker/d7dd648037543d83d48570ed10d4cc25deebc3a89a24ba30bed94c3ae2bc17e3/cpuacct.stat | awk '{SUM+=$2} END { print SUM, strftime(\"%s\") }'"

    #print "New command", command
    tot_time_before = subprocess.check_output(tot_time_cmd, shell=True).rstrip()
    u_s_time_before = subprocess.check_output(u_s_time_cmd, shell=True).rstrip()

    tot_time_before_decoded = tot_time_before.decode('utf-8')
    u_s_time_before_decoded = u_s_time_before.decode('utf-8')

    tot_time_before_decoded_s = tot_time_before_decoded.split(' ', len(tot_time_before_decoded))
    u_s_time_before_decoded_s = u_s_time_before_decoded.split(' ', len(u_s_time_before_decoded))

    print "tot_time_before_decoded, u_s_time_before_decoded", tot_time_before_decoded, u_s_time_before_decoded

    while True:
        time.sleep(pollTime)
        #getValues = "top -b -p "+pid+" -n 1 | tail -n 1 | awk '{print $9, $10, strftime(\"%s\")}'"
        #values = subprocess.check_output(command, shell=True).rstrip()
        tot_time_after = subprocess.check_output(tot_time_cmd, shell=True).rstrip()
        u_s_time_after = subprocess.check_output(u_s_time_cmd, shell=True).rstrip()

        tot_time_after_decoded = tot_time_after.decode('utf-8')
        u_s_time_after_decoded = u_s_time_after.decode('utf-8')

        tot_time_after_decoded_s = tot_time_after_decoded.split(' ', len(tot_time_after_decoded))
        u_s_time_after_decoded_s = u_s_time_after_decoded.split(' ', len(u_s_time_after_decoded))

        print "tot_time_after_decoded, u_s_time_after_decoded", tot_time_after_decoded_s[0], u_s_time_after_decoded_s[1]

        u_s_util = 100 * (float(u_s_time_after_decoded_s[0]) - float(u_s_time_before_decoded_s[0]))/(float(tot_time_after_decoded_s[0]) - float(tot_time_before_decoded_s[0]))
        print "u_s_util",u_s_util

        tot_time_before_decoded_s = tot_time_after_decoded_s
        u_s_time_before_decoded_s = u_s_time_after_decoded_s
        #values_decoded = values.decode('utf-8')
        #print "values_decoded", values_decoded
        # This convert multiline to singleline
        #values_decoded = values_decoded.replace("\n"," ")

        #print "length values_decoded",len(values_decoded.split(' ', len(values_decoded)))
        #nmetrics = len(values_decoded.split(' ', len(values_decoded)))
        #print nmetrics
        #for i in range(0,nmetrics):
        #    print metrics[i][0]

        #print "metrics",metrics
        #values = values_decoded.split(' ', len(values_decoded))
        #print "values", values

        #updateResourceValuesStore(uuid,values)
        #time.sleep(pollTime)

    
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
        msg = "---Check if hresmonAgent is already running. Connection error---"
        print msg
        logger.info(msg)
        sys.exit(0)
    else:
        msg = "hresmonAgent API IP address: "+IP_ADDR
        logger.info(msg)
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