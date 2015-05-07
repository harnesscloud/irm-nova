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

import requests, json, os
import re
#from bottle import route, run,response,request,re
import ConfigParser
#from threading import Thread
import logging
import logging.handlers as handlers
#from pudb import set_trace; set_trace()

#Config and format for logging messages
logger = logging.getLogger("Rotating Log")
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter(fmt='%(asctime)s.%(msecs)d - %(levelname)s: %(filename)s - %(funcName)s: %(message)s', datefmt='%d/%m/%Y %H:%M:%S')
handler = handlers.TimedRotatingFileHandler("n-irm.log",when="H",interval=24,backupCount=0)
## Logging format
handler.setFormatter(formatter)
logger.addHandler(handler)

with open("templates/json_getAvailableResources") as f:
        jsonGetAvRes = f.read()

jsonGetAvResOutputRes = json.loads(jsonGetAvRes)['Output']['Resources'][0]

global CONFIG
if 'CONFIG' not in globals():
    CONFIG = ConfigParser.RawConfigParser()
    CONFIG.read('irm.cfg')

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
    r = requests.post(token_url, data, headers=headers)
    try:
        global token_id
        token_id = r.json()['access']['token']['id']
        #print r.text
    except AttributeError:
        print "N-Irm: [createToken] Unable to use r variable with json. Fault with token_url, or data variables"
        logger.error("Fault with token_url or data variable, caused r to be unusable with json")
     
    if token_id:
            #print token_id
            return token_id
    else:
            return None
    logger.info("Completed!")

def getEndPoint(os_api_url, token_id):
    logger.info("Called")
    endpoints_url = os_api_url+"/v2.0/tokens/"+token_id+"/endpoints"
    headers = {'X-Auth-Token': token_id}

    if str(token_id) not in str(headers):
        raise AttributeError("N-Irm: [getEndPoint] Failure to assign headers. Possibly incorrect token_id")
        logger.error("Failed to assign headers. Possible fault in token_id")

    r = requests.get(endpoints_url, headers=headers)
    try:
        endpoints = r.json()['endpoints']
    except AttributeError:
        print "N-Irm [getEndPoint] Failure to assign endpoints. Possibly incorrect endpoints_url or unable to acces endpoints"
        logger.error("Failed to assign endpoints. Possible incorrect endpoints_url or unable to access endpoints")
    # print endpoints
    for majorkey in endpoints:
        if majorkey['type'] == 'compute':
            global public_url
            public_url = majorkey['publicURL']
    if public_url:
            #print public_url
            return public_url
    else:
            return None
    logger.info("Completed!")


# get hosts from nova and return a list
def getHosts():
    logger.info("Called")
    ## regex check that public url begins with http:// 
    ## token id check that it is of the correct length [32]
    ## general try except in the event of an unexpected error, recommending that 
    ## they check the public url, as named urls may not have been resolved

    headers = {'X-Auth-Token': token_id}
     #headers = None
     #print public_url
     #print token_id
    r = requests.get(public_url+'/os-hosts', headers=headers)
     
     #print r.text
    # print headers
    # print "public url"
    # print public_url
    # print "token id"
    # print token_id
   
    if str(token_id) not in str(headers):
        raise AttributeError("N-Irm: [getHosts] Failure to assign headers. Possibly incorrect token_id")
        logger.error("Failed to assign headers. Possible fault in token_id")
     
    try:
        # this needs to be fixed with a more appropriate error check
        if r.json():
            print "Request OK" 
    except ValueError:
        print "N-Irm: [getHosts] r = requests.get failed. Possible error with public_url or hostname"
        logger.error("Error within public_url or hostname. ")

    hosts = []
    for majorkey in r.json()['hosts']:
            if majorkey['service'] == 'compute':
                hosts.append(majorkey['host_name'])
    if hosts:
            return hosts
    else:
            return None
    logger.info("Completed!")

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
        reservations = {"Reservations":instanceList}
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

    #response.set_header('Content-Type', 'application/json')
    #response.set_header('Accept', '*/*')
    #response.set_header('Allow', 'POST, HEAD')
    #print r.json()
    #print r.json()['server']['id']
    #status = r.json()['server']['status']
    if r:
            return r.json()
    else:
            return None
    logger.info("Completed!")

#@route('/method/verifyResources/<ID>', method='GET')
#def verifyResources(ID):
    ##headers = {'X-Auth-Token': token_id}
    ##r = requests.get(public_url+'/servers/'+ID, headers=headers)
    ##print r.json()['server']['id']
    ##status = getInstanceStatus(ID)
    #info = getInstanceInfo(ID)
    #status = info['server']['status']
    #IP = "100"
    #for private in info['server']['addresses']['private']:
        #if private['OS-EXT-IPS:type'] == "fixed":
            #IP = private['addr']
    ##status = r.json()['server']['status']
    #response.set_header('Content-Type', 'application/json')
    #response.set_header('Accept', '*/*')
    #response.set_header('Allow', 'POST, HEAD')
    #data = {"result":{"Ready":status,"addresses":IP}}
    #if data:
         #return data
    #else:
         #return None

# load resources information not available through nova from file in JSON format
def loadHostList():
     logger.info("Called")
     with open('compute_list') as f:
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

    r = requests.get(public_url+'/os-hosts/'+hostname, headers=headers)
    #print r
    try:
        hostDetails = r.json()
    except ValueError:
        print "N-Irm: [getHostDetails] r = requests.get failed. Possible error with public_url or hostname"
        print ""
        logger.error("Error within public_url or hostname")
    #print hostDetails    
    
    if hostDetails:
       return hostDetails
    else:
       return None
    logger.info("Completed!")

def createListAvailableResources(host_list,public_url,token_id,option):
    # create response structure
    

    logger.info("Called")
    resources = {option:[]}   
    h_list = getHosts()
     
    # loop through all hosts
    for novah in h_list:
        for h in host_list['Machine']:
            if novah == h['host_name']:
                #host_split = h.split()
                # load values
                hostIP = h['IP']
                hostName = h['host_name']
                #costCores = h['Cost']['Cores']
                #costMemory = h['Cost']['Memory']
                #costDisk = h['Cost']['Disk']
                frequency = h['frequency']
                location = h['location']
                #CRSID = location+hostIP+"/machine/"+hostName
                
                                 
                #print hostName,costCores,costMemory,costDisk
                # get details from nova
                 
                hostDetails = getHostDetails(hostName)
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
                    for majorkey in hostDetails['host']:
                        if majorkey['resource']['project'] == '(total)':
                            total_mem = majorkey['resource']['memory_mb'] * int(CONFIG.get('overcommit', 'MEM_RATIO'))
                            total_cpu = majorkey['resource']['cpu'] * int(CONFIG.get('overcommit', 'CPU_RATIO'))
                            total_disk = majorkey['resource']['disk_gb'] * int(CONFIG.get('overcommit', 'DISK_RATIO'))
                        if majorkey['resource']['project'] == '(used_now)':
                            used_mem = majorkey['resource']['memory_mb']
                            used_cpu = majorkey['resource']['cpu']
                            used_disk = majorkey['resource']['disk_gb']
                        # calculate available resources
                        nCores = total_cpu - used_cpu
                        memory = int(total_mem - used_mem - 0.1 * total_mem)
                        disk = total_disk - used_disk
                    # build response
                    jsonGetAvResOutputRes['IP'] = hostIP
                    jsonGetAvResOutputRes['ID'] = hostName
                    jsonGetAvResOutputRes['Attributes']['Cores'] = nCores
                    jsonGetAvResOutputRes['Attributes']['Frequency'] = frequency
                    jsonGetAvResOutputRes['Attributes']['Memory'] = memory
                    jsonGetAvResOutputRes['Attributes']['Disk'] = disk

                    #data = {"ID":hostName, "IP":hostIP, "Type":"Machine","Attributes":{"Cores":nCores,"Frequency":frequency,"Memory":memory,"Disk":disk}}
                    resources[option].append(jsonGetAvResOutputRes)
                    #print "jsonGetAvResOutputRes",json.dumps(jsonGetAvResOutputRes)
                    #print "data",data
                    #resources[option].append(data)
                    #print resources
            #r = json.dumps(resources)
    if "{'Resources': []}" in resources:
        raise AttributeError('N-Irm: [createListAvailableResources] resources variable is empty. Failure to append data variable')
        logger.error("Failed to append 'data' variable. 'Resources' variable empty")

     
    logger.info("Completed!")

    if resources:
        return resources
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
    r = requests.get(public_url+'/flavors', headers=headers)

    for flavor in r.json()['flavors']:
        if "HARNESS" in flavor['name']:
            deleteFlavor(flavor['id'])
            #print flavor

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

    if status:
            return status
    else:
            return None
         
    logger.info("Completed!")

def getImageUUIDbyName(name):
    logger.info("Called")
    headers = {'X-Auth-Token': token_id}

    if str(token_id) not in str(headers):
        raise AttributeError("N-Irm: [getInstanceStatus] Failure to assign headers. Possibly incorrect token_id")
        logger.error("Failed to assign headers. Possible fault in token_id")
    
    #print name
    #print "public_url:",public_url
    r = requests.get(public_url+'/images', headers=headers)
    #print "GLANCE IMAGES",r.text

    for image in r.json()["images"]:
        if image["name"] == name:
            imageId = image["id"]

    return imageId

def getNetUUIDbyName(name):
    logger.info("Called")
    headers = {'X-Auth-Token': token_id}

    if str(token_id) not in str(headers):
        raise AttributeError("N-Irm: [getInstanceStatus] Failure to assign headers. Possibly incorrect token_id")
        logger.error("Failed to assign headers. Possible fault in token_id")
    
    #print "public_url:",public_url
    r = requests.get(public_url+'/os-networks', headers=headers)
    #print "GLANCE IMAGES",r.text

    for net in r.json()["networks"]:
        if net["label"] == name:
            netId = net["id"]

    return netId


def getNetworks():
    logger.info("Called")
    headers = {'X-Auth-Token': token_id}

    if str(token_id) not in str(headers):
        raise AttributeError("N-Irm: [getNetworks]  Failure to assign headers. Possibly incorrect token_id")
        logger.error("Failed to assign headers. Possible fault in token_id")
    
    r = requests.get(public_url+'/os-networks', headers=headers)
    #print r.json()
    networks = []
    for net in r.json()['networks']:
            networks.append(net['label'])

    if len(networks) > 0:
            return networks
    else:
            return None
    logger.info("Completed!")

def checkResources(data):
    logger.info("Called")
    #print "data in checkResources before",data
    
    
    reply = {"Reservations":[]}
    if data['Reservations']:
        #print "Data not empty"
        req = data
        try:            
            for ID in req['Reservations']:
                status = "false"
                osstatus = "BUILD"               
                try:
                    while osstatus == "BUILD":
                        info = getInstanceInfo(ID)
                        osstatus = info['server']['status']
                        #print osstatus
                    if osstatus == "ACTIVE":
                        status = "true"
                        #print "setting status"

                except TypeError:
                    print "N-Irm: [verifyResources] Payload present but fault in ID. Could be missing or incorrect."
                    print " "
                    logger.error("Fault in the payload's ID. Either missing or incorrect, must match an existent ID")
                IP = "100"
                # change to private to vmnet in field below
                #print info['server']
                for private in info['server']['addresses'][CONFIG.get('network', 'NET_ID')]:
                    if private['OS-EXT-IPS:type'] == CONFIG.get('network', 'IP_TYPE'):
                        IP = private['addr']
                        #print "IP:", IP
                #status = r.json()['server']['status']
                #response.set_header('Content-Type', 'application/json')
                #response.set_header('Accept', '*/*')
                #response.set_header('Allow', 'POST, HEAD')
                data = {"ID":ID,"Ready":status,"Address":IP}
                reply["Reservations"].append(data)
            # When there is no ID, this case occurs    
            if ID in req['Reservations'] is None:
               raise UnboundLocalError('N-Irm: [verifyResources] Attempting to use ID variable before it has a value. Ensure payload has "<instanceID>"')
               logger.error("ID has not been assigned before being used. Ensure payload has a present and correct instance ID")
        except UnboundLocalError:
            raise UnboundLocalError("N-Irm: [verifyResources] Attempting to reference variable before it has been assigned. Payload may be missing. Or ID is missing or empty. Please check payload!")
            logger.error("Variable being referenced before payload or ID is assigned, possibly missing or empty. ")
    else:
        print "Data empty"

    #print "reply in checkResources after",reply
    return reply
    logger.info("Completed!")

def deleteResources(reservations):
    logger.info("Called")
    headers = {'X-Auth-Token': token_id}
    try:
        for ID in reservations['Reservations']:              
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
        return "DONE"
        if ID in reservations['Reservations'] is None:               
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
        return error
        logger.error(error)
    logger.info("Completed!")
    return r

def getInstanceType(host):
    logger.info("Called")
    headers = {'X-Auth-Token': token_id}

    if str(token_id) not in str(headers):
        raise AttributeError("N-Irm: [getNetworks]  Failure to assign headers. Possibly incorrect token_id")
        logger.error("Failed to assign headers. Possible fault in token_id")
    
    r = requests.get(public_url+'/os-hypervisors/detail', headers=headers)
    #print r.json()
    htype = ""
    result = r.json()
    for h in result['hypervisors']:
        if h['service']['host'] == host:
            htype = h['hypervisor_type']
            break

    return htype
    #if len(networks) > 0:
    #        return networks
    #else:
    #        return None
    logger.info("Completed!")