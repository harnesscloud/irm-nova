#!/usr/bin/env python
# Description
# This is the library that interacts with IRM-nova from one side and OpenStack from the other
#
#
#
# Status
# - all functions are implemented and seem to be working
#
#
#

import requests, json, os, copy
import re
#from bottle import route, run,response,request,re
import ConfigParser
#from threading import Thread
import logging
import logging.handlers as handlers
#from pudb import set_trace; set_trace()

def createLogger():
    #Config and format for logging messages
    global logger
    logger = logging.getLogger("Rotating Log")
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(fmt='%(asctime)s.%(msecs)d - %(levelname)s: %(filename)s - %(funcName)s: %(message)s', datefmt='%d/%m/%Y %H:%M:%S')
    handler = handlers.TimedRotatingFileHandler("n-irm.log",when="H",interval=24,backupCount=0)
    ## Logging format
    handler.setFormatter(formatter)
    if not logger.handlers:
        logger.addHandler(handler)

def libnovaInit(conf_file):
    global CONFIG
    if 'CONFIG' not in globals():
        CONFIG = ConfigParser.RawConfigParser()
        CONFIG.read(conf_file)

def getIP(url):
    logger.info("Called")
    address_regexp = re.compile ('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    try:
        result = address_regexp.search(url)
    except AttributeError:
        print "N-Irm: [getIP] Failed to get IP. result variable could not search url. Possible url fault"
        logger.error("url error caused result variable to have incorrect assignment")

    if result:
        return result.group()
    else:
        return None
    logger.info("Completed!")

def createToken(os_api_url, tenantName, username, password):
    logger.info("Called")
    headers = {'content-type': 'application/json'}
    data = json.dumps({"auth": {"tenantName": tenantName, "passwordCredentials": {"username": username, "password": password}}})
    token_url = os_api_url+"/v2.0/tokens"
    #print "token_url: "+token_url
    try:
        r = requests.post(token_url, data, headers=headers)
        global token_id
        token_id = r.json()['access']['token']['id']
        #print r.text
    except AttributeError:
        print "N-Irm: [createToken] Unable to use r variable with json. Fault with token_url, or data variables"
        logger.error("Fault with token_url or data variable, caused r to be unusable with json")
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        logger.error(error)
        return error

    if token_id:
        logger.info("Created token: "+token_id)
        return token_id
    else:
        return None
    logger.info("Completed!")

def getEndPoints(os_api_url, token_id):
    logger.info("Called")
    endpoints_url = os_api_url+"/v2.0/tokens/"+token_id+"/endpoints"
    headers = {'X-Auth-Token': token_id}

    urls = []

    if str(token_id) not in str(headers):
        raise AttributeError("N-Irm: [getEndPoints] Failure to assign headers. Possibly incorrect token_id")
        logger.error("Failed to assign headers. Possible fault in token_id")

    try:
        r = requests.get(endpoints_url, headers=headers)
        endpoints = r.json()['endpoints']
    except AttributeError:
        print "N-Irm [getEndPoints] Failure to assign endpoints. Possibly incorrect endpoints_url or unable to acces endpoints"
        logger.error("Failed to assign endpoints. Possible incorrect endpoints_url or unable to access endpoints")
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        logger.error(error)
        return error

    # print endpoints
    for majorkey in endpoints:
        if majorkey['type'] == 'compute':
            global public_url
            public_url = majorkey['publicURL']
            #print public_url
            urls.append(public_url)
        if majorkey['type'] == 'network':
            global net_url
            net_url = majorkey['publicURL']
            #print net_url
            urls.append(net_url)

    if urls:
        logger.info("Urls: "+str(urls))
        return urls
    else:
        return None
    logger.info("Completed!")


# get hosts from nova and return a list
def getHosts():
    logger.info("Called")
    headers = {'X-Auth-Token': token_id}
   
    if str(token_id) not in str(headers):
        raise AttributeError("N-Irm: [getHosts] Failure to assign headers. Possibly incorrect token_id")
        logger.error("Failed to assign headers. Possible fault in token_id")
     
    try:
        r = requests.get(public_url+'/os-hosts', headers=headers)
        # this needs to be fixed with a more appropriate error check
        if r.json():
            print "Request OK"
            #logger.info("Hosts: "+r.text)
    except ValueError:
        print "N-Irm: [getHosts] r = requests.get failed. Possible error with public_url or hostname"
        logger.error("Error within public_url or hostname. ")
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        logger.error(error)
        return error

    hosts = []
    for majorkey in r.json()['hosts']:
        if majorkey['service'] == 'compute':
            hosts.append(majorkey['host_name'])

    logger.info("Completed!")
    if hosts:
        return hosts
    else:
        return None
    

def getListInstances():
    logger.info("Called")
    headers = {'X-Auth-Token': token_id}
    #headers = None
    subname = "HARNESS"      
    if str(token_id) not in str(headers):
        raise AttributeError("N-Irm: [getHostDetails] Failure to assign headers. Possibly incorrect token_id")
        logger.error("Failed to assign headers. Possible fault in token_id")

    r = requests.get(public_url+'/servers', headers=headers)
    #print r
    reservations = None
    try:
        instanceList = []
        response = r.json()
        #print response
        for instance in response['servers']:
            #print "INSTANCE:",instance['name']
            if subname in instance['name']:
                #print "GOT ",subname, instance
                instanceList.append(instance['id'])
        #print instanceList
        reservations = {"ReservationID":instanceList}
        #print json.dumps(reservations)
    except ValueError:
        print "N-Irm: [getInstanceList] r = requests.get failed. Possible error with public_url or hostname"
        print ""
        logger.error("Error within public_url or hostname")
    #print hostDetails    
    
    if reservations:
       return reservations
    else:
       return None
    logger.info("Completed!")

#@route('/method/checkReservationInfo/<ID>', method='GET')
def getInstanceInfo(ID):
    logger.info("Called")
    headers = {'X-Auth-Token': token_id}
    if str(token_id) not in str(headers):
        raise AttributeError("N-Irm: [getInstanceInfo] Failure to assign headers. Possibly incorrect token_id")
        logger.error("Failed to assign headers. Possible fault in token_id")
    
    r = requests.get(public_url+'/servers/'+ID, headers=headers)
    logger.info("Info for instance: "+ID)
    logger.info("Completed!")
    if r:
        return r.json()
    else:
        return None

# load resources information not available through nova from file in JSON format
def loadHostList():
     logger.info("Called")
     hostlistfile = CONFIG.get('main','HOSTLIST')
     with open(hostlistfile) as f:
            try:
                hosts = json.load(f)
            except AttributeError:
                print "N-Irm [loadHostList] Failed to load variable f into hosts"
                logger.error("Attempt to load variable f into hosts failed")

            f.close()

     if hosts:
        return hosts
     else:
        return None
     logger.info("Completed!")


def getHostDetails(hostname):
    logger.info("Called")
    headers = {'X-Auth-Token': token_id}
    #headers = None       
    if str(token_id) not in str(headers):
        raise AttributeError("N-Irm: [getHostDetails] Failure to assign headers. Possibly incorrect token_id")
        logger.error("Failed to assign headers. Possible fault in token_id")

    try:
        r = requests.get(public_url+'/os-hosts/'+hostname, headers=headers)
        hostDetails = r.json()
        logger.info("Host Details: "+json.dumps(hostDetails))
    except ValueError:
        print "N-Irm: [getHostDetails] r = requests.get failed. Possible error with public_url or hostname"
        print ""
        logger.error("Error within public_url or hostname")
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        logger.error(error)
        return error
    #print hostDetails    
    
    logger.info("Completed!")
    if hostDetails:
       return hostDetails
    else:
       return None
    
Machines = None

def createListAvailableResources(public_url,token_id,option):
    logger.info("Called")
    res = {option:{}}
    h_list = getHosts()
    #print "h_list",h_list
    global Machines
    
    if Machines == None:
       Machines = {}
       try:
   	      path = os.path.dirname(os.path.abspath(__file__))
	      with open(path + '/machines.json') as data_file:    
   		     Machines = json.load(data_file)
   		     
       except:
          pass

    mem_pr = float(CONFIG.get('overcommit','MEM_PRESERVE'))
    if mem_pr < 100:
        mem_pr = mem_pr / 100
    else:
        mem_pr = 0.1

    # loop through all hosts
    for novah in h_list:
        # get details from nova
        hostDetails = getHostDetails(novah)
        itype = getInstanceType(novah)
        #print hostDetails
        nCores = 0
        memory = 0
        total_cpu = 0
        used_cpu = 0
        total_mem = 0
        used_mem = 0
        total_disk = 0
        used_disk = 0
        
      
        # load detail from nova reply
        if 'host' in hostDetails:
            #print "::::>", hostDetails['host']
            for majorkey in hostDetails['host']:
                if majorkey['resource']['project'] == '(total)':
                    total_mem = majorkey['resource']['memory_mb'] * int(CONFIG.get('overcommit', 'MEM_RATIO'))
                    total_cpu = majorkey['resource']['cpu'] * int(CONFIG.get('overcommit', 'CPU_RATIO'))
                    total_disk = majorkey['resource']['disk_gb'] * int(CONFIG.get('overcommit', 'DISK_RATIO'))
                    
                    for m in Machines:
                       if m in novah:
                          if "Cores" in Machines[m]:
                             total_cpu = Machines[m]["Cores"]
                          if "Memory" in Machines[m]:
                             total_memory = Machines[m]["Memory"]
                          break   
                    
                if majorkey['resource']['project'] == '(used_now)':
                    used_mem = majorkey['resource']['memory_mb']
                    used_cpu = majorkey['resource']['cpu']
                    used_disk = majorkey['resource']['disk_gb']
                # calculate available resources
                

                nCores = total_cpu - used_cpu
                # memory is calculated 10% less than actual value to avoid commiting it all
                memory = int(total_mem - used_mem - mem_pr * total_mem)
                disk = total_disk - used_disk

            
                  
            res[option][novah] = {'Type':'Machine','Attributes':{'Cores':nCores,"Memory":memory}}

            if itype not in ["docker","LXC"]:
                #print "itype in createListAvailableResources 1",itype
                res[option][novah]['Attributes']['Disk'] = disk
            #else:
                #print "itype in createListAvailableResources 2",itype
                
                

    if "{'Resources': []}" in res:
        raise AttributeError('N-Irm: [createListAvailableResources] resources variable is empty. Failure to append data variable')
        logger.error("Failed to append 'data' variable. 'Resources' variable empty")
     
    logger.info("Completed!")

    if res:
        return res
    else:
        return None

def createFlavor(name,vcpu,ram,disk):
    logger.info("Called")
    headers = {'content-type': 'application/json','X-Auth-Token': token_id}
    
    if str(token_id) not in str(headers):
        raise AttributeError("N-Irm: [createFlavor] Failure to assign headers. Possibly incorrect token_id")
        logger.error("Failed to assign headers. Possible fault in token_id")
    
    data = json.dumps({"flavor": {\
        "name": name,\
        "ram": ram,\
        "vcpus": vcpu,\
        "disk": disk/1024,\
        "id": name}})
    # add here a check if that flavor name exists already and in that case return the correspondent ID

        # add here a check if that flavor name exists already and in that case return the correspondent ID
    # without trying to create a new one as it will fail
    r = requests.post(public_url+'/flavors', data, headers=headers)

    #print r.json()
    logger.info("Completed!")

def deleteFlavor(ID):
    logger.info("Called")
    headers = {'X-Auth-Token': token_id}
    if str(token_id) not in str(headers):
        raise AttributeError("N-Irm: [deleteFlavor] Failure to assign headers. Possibly incorrect token_id")
        logger.error("Failed to assign headers. Possible fault in token_id")

    r = requests.delete(public_url+'/flavors/'+ID, headers=headers)
    logger.info("Completed!")

def cleanFlavors():
    logger.info("Called")
    headers = {'X-Auth-Token': token_id}
    try:
        r = requests.get(public_url+'/flavors', headers=headers)

        for flavor in r.json()['flavors']:
            if "HARNESS" in flavor['name']:
                deleteFlavor(flavor['id'])
                #print flavor
    except ValueError:
        error = {"message":"ValueError","code":"500"}
        print error
        logger.error(error)
        return error
    except requests.exceptions.RequestException:
        error = {"message":"RequestException","code":"500"}
        print error
        logger.error(error)
        return error

    logger.info("Completed!")

def createRandomID(size):
    import binascii
    return binascii.b2a_hex(os.urandom(size))
    logger.info("Random ID generated")

def getInstanceStatus(ID):
    logger.info("Called")
    headers = {'X-Auth-Token': token_id}
    
    if str(token_id) not in str(headers):
        raise AttributeError("N-Irm: [getInstanceStatus] Failure to assign headers. Possibly incorrect token_id")
        logger.error("Failed to assign headers. Possible fault in token_id")
    
    r = requests.get(public_url+'/servers/'+ID, headers=headers)
    
    #print r.json()['server']['id']
    try:
        status = r.json()['server']['status']
    except TypeError:
        print "N-Irm: [getInstanceStatus] Fault in ID. Cannot access ['server'] ['status']"

    logger.info("Completed!")
    if status:
        return status
    else:
        return None

def getImageUUIDbyName(name):
    logger.info("Called")
    headers = {'X-Auth-Token': token_id}

    if str(token_id) not in str(headers):
        raise AttributeError("N-Irm: [getInstanceStatus] Failure to assign headers. Possibly incorrect token_id")
        logger.error("Failed to assign headers. Possible fault in token_id")
    
    r = requests.get(public_url+'/images', headers=headers)

    try:
        imageId=""
        for image in r.json()["images"]:
            if image["name"] == name:
                imageId = image["id"]
                break
            else:
                imageId = "Image Not Found"
            #print imageId
    except Exception.message, e:
        response.status = 500
        error = {"message":e,"code":response.status}
        logger.error(error)
        return error

    logger.info("Completed!")
    return imageId

def getNetUUIDbyName(name):
    logger.info("Called")
    headers = {'content-type': 'application/json','X-Auth-Token': token_id}

    if str(token_id) not in str(headers):
        raise AttributeError("N-Irm: [getNetUUIDbyName] Failure to assign headers. Possibly incorrect token_id")
        logger.error("Failed to assign headers. Possible fault in token_id")

    try:
        r = requests.get(public_url+'/os-networks', headers=headers)
        netId = ""
        for net in r.json()["networks"]:
            if net["label"] == name:
                netId = net["id"]
                break
            else:
                netId = "Net ID not Found"
    except Exception.message, e:
        response.status = 500
        error = {"message":e,"code":response.status}
        logger.error(error)
        return error

    logger.info("Completed!")
    return netId

def getSubnetUUIDbyName(name):
    logger.info("Called")
    headers = {'content-type': 'application/json','X-Auth-Token': token_id}
    if str(token_id) not in str(headers):
        raise AttributeError("N-Irm: [getSubnetUUIDbyName] Failure to assign headers. Possibly incorrect token_id")
        logger.error("Failed to assign headers. Possible fault in token_id")

    try:
        r = requests.get(net_url+'/v2.0/subnets', headers=headers)
        #print "response json",r.json() 
        subnetId = ""
        hname = "HARNESS-"+name
        #print "hname",hname
        for subnet in r.json()["subnets"]:
            if subnet["name"] == hname:
                subnetId = subnet["id"]
                break
            else:
                subnetId = "Net ID not Found"
    except Exception.message, e:
        response.status = 500
        error = {"message":e,"code":response.status}
        logger.error(error)
        return error

    logger.info("Completed!")
    return subnetId

def getMGTSubnetByNetUUID(netuuid,userSubnetUUID):
    logger.info("Called")
    headers = {'content-type': 'application/json','X-Auth-Token': token_id}
    #print "token_id",token_id

    if str(token_id) not in str(headers):
        raise AttributeError("N-Irm: [getInstanceStatus] Failure to assign headers. Possibly incorrect token_id")
        logger.error("Failed to assign headers. Possible fault in token_id")

    try:
        #print "userSubnetUUID",userSubnetUUID
        #print "net_url",net_url
        r = requests.get(net_url+'/v2.0/networks', headers=headers)
        subnetId = ""
        #print "response json",r.json()
        for net in r.json()["networks"]:
            #print net
            if net["id"] == netuuid:
                for sub in net['subnets']:
                    if sub != userSubnetUUID:
                        subnetId = sub
                        break
                else:
                    continue
                break
            else:
                subnetId = "Net ID not Found"
    except Exception.message, e:
        response.status = 500
        error = {"message":e,"code":response.status}
        logger.error(error)
        return error

    except Exception, e:
        #response.status = 404
        print "ERROR",e
        error = {"message":e,"code":404}
        logger.error(error)
        return error

    logger.info("Completed!")
    return subnetId

def createPort(netuuid,mgtSubnetUUID,userSubnetUUID,portName):
    logger.info("Called")
    headers = {'content-type': 'application/json','X-Auth-Token': token_id}

    if str(token_id) not in str(headers):
        raise AttributeError("N-Irm: [getInstanceStatus] Failure to assign headers. Possibly incorrect token_id")
        logger.error("Failed to assign headers. Possible fault in token_id")

    try: 
        data = json.dumps({"port": {\
            "name": portName,\
            "network_id": netuuid,\
            "fixed_ips":[{\
                "subnet_id": mgtSubnetUUID,\
            },\
            {\
                "subnet_id": userSubnetUUID}]}})

        #print data
        r = requests.post(net_url+'/v2.0/ports', data, headers=headers).json()

        portID = ""
        
        if "port" not in r:
           raise Exception("subnet not valid!")
            
        if r["port"]["id"]:
            portID = r["port"]["id"]
            print portID
        else:
            portID = "Port ID not found"

    except Exception as e:
        error = {"message":e.message,"code": 500}
        logger.error(error)
        return error

    except Exception, e:
        #response.status = 404
        print "ERROR",e
        error = {"message":e,"code":404}
        logger.error(error)
        return error

    logger.info("Completed!")
    return portID

def getNetworks():
    logger.info("Called")
    headers = {'X-Auth-Token': token_id}

    if str(token_id) not in str(headers):
        raise AttributeError("N-Irm: [getNetworks]  Failure to assign headers. Possibly incorrect token_id")
        logger.error("Failed to assign headers. Possible fault in token_id")
    
    r = requests.get(public_url+'/os-networks', headers=headers)
    networks = []
    for net in r.json()['networks']:
        networks.append(net['label'])

    logger.info("Completed!")
    if len(networks) > 0:
        return networks
    else:
        return None

def checkResources(data):
    logger.info("Called")
    reply = {"Instances":{}}
    if data['ReservationID']:
        #print "Data not empty"
        req = data
        try:            
            for ID in req['ReservationID']:
                print "ID",ID
                ERROR = False
                status = "false"
                osstatus = "BUILD"               
                try:
                    while osstatus == "BUILD":
                        info = getInstanceInfo(ID)
                        osstatus = info['server']['status']
                        logger.info("Status: "+osstatus)
                    if osstatus == "ACTIVE":
                        status = "true"
                        logger.info("Status: "+osstatus)
                        #print "setting status"

                except TypeError:
                    print "N-Irm: [verifyResources] Payload present but fault in ID. Could be missing or incorrect."
                    #print " "
                    logger.error("Fault in the payload's ID. Either missing or incorrect, must match an existent ID")
                    ERROR = True

                if not ERROR:
                    IP = []
                    # change to private to vmnet in field below
                    for private in info['server']['addresses'][CONFIG.get('network', 'NET_ID')]:
                        if private['OS-EXT-IPS:type'] == CONFIG.get('network', 'IP_TYPE'):
                            IP.append(private['addr'])
                            #print "IP:", IP

                    #data = {"Ready":status,"Address":IP}
                    data = {"Ready":status,"Address":[';'.join(IP)]}                    
                    reply["Instances"][ID] = data
            # When there is no ID, this case occurs    
            if ID in req['ReservationID'] is None:
               raise UnboundLocalError('N-Irm: [verifyResources] Attempting to use ID variable before it has a value. Ensure payload has "<instanceID>"')
               logger.error("ID has not been assigned before being used. Ensure payload has a present and correct instance ID")
        except UnboundLocalError:
            raise UnboundLocalError("N-Irm: [verifyResources] Attempting to reference variable before it has been assigned. Payload may be missing. Or ID is missing or empty. Please check payload!")
            logger.error("Variable being referenced before payload or ID is assigned, possibly missing or empty. ")
    else:
        raise TypeError("N-Irm: [checkResources] data is empty!")

    logger.info("Completed!")

    return reply

def deleteResources(reservations):
    logger.info("Called")
    headers = {'X-Auth-Token': token_id}
    try:
        for ID in reservations['ReservationID']:              
            try:
                #forces it to break is incorrect ID
                info = getInstanceInfo(ID)
                osstatus = info['server']['status']
                #deletion of correct ID
                r = requests.delete(public_url+'/servers/'+ID, headers=headers)
            except TypeError:
                print " "
                raise TypeError("N-Irm: [releaseResources] Payload present but fault in ID. Could be missing or incorrect.")
                logger.error("Payload was incorrect. ID possibly missing or incorrect")
        # Thrown to enforce exception below
        logger.info("Completed!")
        return "DONE"
        if ID in reservations['ReservationID'] is None:               
            raise UnboundLocalError
    except UnboundLocalError:
        raise UnboundLocalError("N-Irm: [releaseResources] Payload may be missing. Or ID is missing or empty. Please check Payload!")
        logger.error("Fault with payload and ID. If payload is present, Id may be missing or empty")
        return error

def createResources(data):
    logger.info("Called")
    headers = {'content-type': 'application/json','X-Auth-Token': token_id}
    try:
        r = requests.post(public_url+'/servers', data, headers=headers)
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        logger.error(error)
        return error
    logger.info("Completed!")
    return r

def getInstanceName(uuid):
    print "In getInstanceName"
    logger.info("Called")
    headers = {'X-Auth-Token': token_id}

    try:

        if str(token_id) not in str(headers):
            raise AttributeError("N-Irm: [getNetworks]  Failure to assign headers. Possibly incorrect token_id")
            logger.error("Failed to assign headers. Possible fault in token_id")
        
        r = requests.get(public_url+'/servers/'+uuid, headers=headers)
        result = r.json()
        instanceName = result["server"]["OS-EXT-SRV-ATTR:instance_name"]
    except AttributeError:
        print "N-Irm: [getNetworks]  Failure to assign headers. Possibly incorrect token_id"
        logger.error("Failed to assign headers. Possible fault in token_id")

    logger.info("Completed!")
    return instanceName

def getInstanceType(host):
    logger.info("Called")
    headers = {'X-Auth-Token': token_id}

    if str(token_id) not in str(headers):
        raise AttributeError("N-Irm: [getNetworks]  Failure to assign headers. Possibly incorrect token_id")
        logger.error("Failed to assign headers. Possible fault in token_id")
    
    try:
        r = requests.get(public_url+'/os-hypervisors/detail', headers=headers)
        htype = ""
        result = r.json()
        for h in result['hypervisors']:
            if h['service']['host'] == host:
                htype = h['hypervisor_type']
                break
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        logger.error(error)
        return error

    logger.info("Instance Type: "+htype)
    logger.info("Completed!")
    return htype
