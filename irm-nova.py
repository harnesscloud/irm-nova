#!/usr/bin/env python
# Description
#
#
#
#
# Status
# - all APIs are implemented and seem to be working
# - loading additional info of computes not available through openstack from compute_list file
#
#
#
# How it works
# - check the help
#    - ./irm-nova.py -h
#    - configuration files
#       - general: irm.cfg
#       - nova related: compute_list, this need to be filled with nova-compute(s) values
# - start the API
#    - e.g. ./irm-nova.py -a 192.168.56.108:5000 -t admin -u admin -w password -i eth0 -p 8888
#    - e.g. ./irm-nova.py -c irm.cfg
#    - it can also be started through supervisor
#         - supervisord -c ./supervisord.conf
#
# - test
#    - unitTest
#       - cd tests
#       - ./test_irm-nova.py -i <irm-nova IP> -p <irm-nova PORT>
#    - use any rest client (e.g. RESTClient for firefox) to make calls to the API
#
# - available APIs
#   - /method/getAvailableResources
#   - /method/getResourceTypes
#   - /method/calculateResourceCapacity
#   - /method/calculateResourceAgg
#   - /method/verifyResources
#   - /method/reserveResources
#   - /method/releaseResources
#
#
#
#
#
#
#
#
#

#from openstack import OpenStackCloud
import requests, json, pickle, sys, os, subprocess,optparse, time, thread
import re
from bottle import route, run,response,request,re
import ConfigParser
from threading import Thread
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
        token_id = r.json()['access']['token']['id']
        print r.text
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
             costCores = h['Cost']['Cores']
             costMemory = h['Cost']['Memory']
             costDisk = h['Cost']['Disk']
             frequency = h['frequency']
             location = h['location']
             CRSID = location+hostIP+"/machine/"+hostName
            
                             
             #print hostName,costCores,costMemory,costDisk
             # get details from nova
             
             hostDetails = getHostDetails(hostName)
             nCores = 0
             Memory = 0
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
                     Memory = int(total_mem - used_mem - 0.1 * total_mem)
                     disk = total_disk - used_disk
                 # build response
                 data = {"ID":CRSID, "IP":hostIP, "Type":"Machine","Attributes":{"Cores":nCores,"Frequency":frequency,"Memory":Memory,"Disk":disk},"Cost":{"Cores":costCores,"Memory":costMemory,"Disk":costDisk}}
                 resources[option].append(data)
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


# To be fixed with GET
@route('/method/getAvailableResources/', method='POST')
@route('/method/getAvailableResources', method='POST')
def getAvailableResources(): 
    logger.info("Called")

    try:    	
        option = "Resources"   
        resources = createListAvailableResources(host_list,public_url,token_id,option) 
        r = {"result":resources}       

        result = json.dumps(r)
        
    	             
    except Exception.message, e:
       response.status = 400
       error = {"message":e,"code":response.status}
       return error
       logger.error(error)
    
    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'POST, HEAD') 

    logger.info("Completed")   
    return result
    
# To be fixed with GET
@route('/method/getResourceTypes/', method='POST')
@route('/method/getResourceTypes', method='POST')
def getResourceTypes():
    logger.info("Called")
    try:
        #data = createListAvailableResources(host_list,public_url,token_id)
        types = {"Types":[]}
        data = {"Type":"Machine","Attributes":{"Cores":{"Description":"Number of cores","DataType":"int"},"Frequency":{"Description":"Processor frequency","DataType":"double"},"Memory":{"Description":"Amount of RAM","DataType":"int"},"Disk":{"Description":"Disk capacity","DataType":"int"}}}
        types["Types"].append(data)
               
        result = {"result":types}
        r = json.dumps(result)
        
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        return error
        logger.error(error)
    
    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'POST, HEAD') 
    
    if r:
        return r
    else:
        return None
    logger.info("Completed!")

def registerIRM():
    logger.info("Called")
#    print "ip:%s , port:%s, crs: %s" % (IP_ADDR, PORT_ADDR, CONFIG.get('CRS', 'CRS_URL'))
    headers = {'content-type': 'application/json'}
    try:
       data = json.dumps(\
       {\
       "Manager":"IRM",\
       "Hostname":IP_ADDR,\
       "Port":PORT_ADDR,\
       "Name":"IRM-NOVA"\
       })
    except AttributeError:
    	logger.error("Failed to json.dumps into data")
   
    # add here a check if that flavor name exists already and in that case return the correspondent ID
    # without trying to create a new one as it will fail
    r = requests.post(CONFIG.get('CRS', 'CRS_URL')+'/method/addManager', data, headers=headers)

    logger.info("Completed!")

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

# To be fixed with GET
@route('/method/checkReservationInfo/<ID>', method='POST')
def getInstanceInfo(ID):
    logger.info("Called")
    headers = {'X-Auth-Token': token_id}
    if str(token_id) not in str(headers):
    	raise AttributeError("N-Irm: [getInstanceInfo] Failure to assign headers. Possibly incorrect token_id")
    	logger.error("Failed to assign headers. Possible fault in token_id")
    
    r = requests.get(public_url+'/servers/'+ID, headers=headers)

    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'POST, HEAD')
    #print r.json()
    #print r.json()['server']['id']
    #status = r.json()['server']['status']
    if r:
         return r.json()
    else:
         return None
    logger.info("Completed!")


# To be fixed with GET
#@route('/method/verifyResources/<ID>', method='POST')
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

def checkResources(data):
    logger.info("Called")
    #print "data in checkResources",data
    reply = {"Reservations":[]}
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
            for private in info['server']['addresses'][CONFIG.get('network', 'NET_ID')]:
                if private['OS-EXT-IPS:type'] == CONFIG.get('network', 'IP_TYPE'):
                    IP = private['addr']
            #status = r.json()['server']['status']
            response.set_header('Content-Type', 'application/json')
            response.set_header('Accept', '*/*')
            response.set_header('Allow', 'POST, HEAD')
            data = {"ID":ID,"Ready":status,"Address":IP}
            reply["Reservations"].append(data)
        # When there is no ID, this case occurs    
        if ID in req['Reservations'] is None:
           raise UnboundLocalError('N-Irm: [verifyResources] Attempting to use ID variable before it has a value. Ensure payload has "<instanceID>"')
           logger.error("ID has not been assigned before being used. Ensure payload has a present and correct instance ID")
    except UnboundLocalError:
        raise UnboundLocalError("N-Irm: [verifyResources] Attempting to reference variable before it has been assigned. Payload may be missing. Or ID is missing or empty. Please check payload!")
        logger.error("Variable being referenced before payload or ID is assigned, possibly missing or empty. ")

    return reply
    logger.info("Completed!")

# To be fixed with GET
@route('/method/verifyResources/', method='POST')
@route('/method/verifyResources', method='POST')
def verifyResources():
    logger.info("Called")
    try:
        req = json.load(request.body)
    except ValueError:
        print "N-Irm: [verifyResources] Attempting to load a non-existent payload, please enter desired payload"   
        print " "
        logger.error("Payload was empty. A payload must be present")
    
   
    #print "in verifyResources"
   # print reply
    #network = getNetworks()[0]
    #print network
    try:
    	reply = checkResources(req)

        option = "AvailableResources"
        resources = createListAvailableResources(host_list,public_url,token_id,option)
        #print resources
        #print reply
        #reply["Reservations"]
        #print reply
        reply.update(resources)
        #print reply
        result = {"result":reply}
        #print result
        jsondata = json.dumps(result)
        return jsondata
    
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        return error
        logger.error(error)
    logger.info("Completed!")

@route('/method/reserveResources/', method='POST')
@route('/method/reserveResources', method='POST')
def reserveResources():
    logger.info("Called")
    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'POST, HEAD')
    try:
        # get the body request
      #  print request.body
        try:
            req = json.load(request.body)
        except ValueError:
        	print "N-Irm [reserveResources] Attempting to load a non-existent payload please enter desired payload"
        	logger.error("Payload was empty or incorrect. A payload must be present and correct")
        	print " "

        cleanFlavors()
        reservation = {"Reservations":[]}
        # loop through all requested resources
        name = ""
        #print "============> ", req['Resources']

        for resource in req['Resources']:
           #print resource
           # load values
           IP = resource['IP']
           #print "Image", resource['Image']
           if 'Image' in resource:
               image = resource['Image']
           else:
               image = CONFIG.get('CRS', 'DEFAULT_IMAGE')
           #print "Image after", image
           user_data = ''
           if 'UserData' in resource:
               user_data = resource['UserData']

           if 'Cores' in resource['Attributes']:
               vcpu = resource['Attributes']['Cores']
           else:
               vcpu = 1
           if 'Memory' in resource['Attributes']:
               memory = resource['Attributes']['Memory']
           else:
               memory = 2048
           if 'Disk' in resource['Attributes']:
               disk = resource['Attributes']['Disk']
           else:
               disk = 20 * 1024
           if 'Frequency' in resource['Attributes']:
               frequency = resource['Attributes']['Frequency']
           else:
               frequency = 2.4
           #print IP,vcpu,memory,disk,frequency, image
           #count = resource['NumInstances']
           #count = 1
           #print "COUNT: ",count
           # get host_name from IP in the request
           hostName = ""
           h_list = getHosts()
           #print h_list
          # print IP
          
           for novah in h_list:
               #print host_list
               for h in host_list['Machine']:
                   #print novah, h
                   if novah == h['host_name']:
                       # load values
                       if h['IP'] == IP:
                          hostName = h['host_name']
                          # build host for availability_zone option to target specific host
                          host = "nova:"+hostName
                          name = "HARNESS-"+createRandomID(6)
                          # create ID for flavor creation
                          #tmpID = createRandomID(15)
                          #print tmpID
                          createFlavor(name,vcpu,memory,disk)
                          headers = {'content-type': 'application/json','X-Auth-Token': token_id}
                          # build body for nova api
                          # create instances up to the number in the request
                          #for i in xrange(0,count):
                          #print "Image after", image
                          dobj = {"server" : {\
                                      "name" : name,\
                                      "imageRef" : image, \
                                      #"imageRef" : "162bb278-76cf-4dd2-8560-e3367050d32a", \
                                      #"imageRef" : "3184a7b0-673e-4c17-9243-9241c914eec8",\
                                      #"imageRef" : "185982bc-5eab-4cde-8061-02d519dca5ef",\
                                      "flavorRef" : name,\
                                      "min_count": 1,\
                                      "max_count": 1,\
                                      "availability_zone":host}}
                          if CONFIG.has_option('network', 'UUID'):
                            dobj["server"]["networks"] = [ { "uuid": CONFIG.get('network', 'UUID') } ]
                             
                          #print dobj
                                                                                      
                          data = json.dumps(dobj)
                          #print "data before creating instance: ", data
                          #print "Creating instance number "+str(i+1)+", name "+name
                          print "Creating instance "+name
                          r = requests.post(public_url+'/servers', data, headers=headers)
                          #print "====> ", str(r.json())
                          #print r.json()
                          try:
                            ID = r.json()['server']['id']
                            #print r.json()
                          except KeyError, msg:
                            print "N-Irm: [reserveResources] Error within payload, please check spelling"
                            logger.error("KeyError in payload, please check spelling of attributes")
                          #print getInstanceInfo(ID)
                          #print ID
                          #status = ""
                                  #while (status != "ACTIVE") and (status !="ERROR"):
                                  #    status = getInstanceStatus(ID)
                                  #    print "Status of "+name+" "+status
                          #instanceID = {"InfReservID":ID}
                          try:
                            reservation["Reservations"].append(ID)
                          except UnboundLocalError:
                            print "N-Irm [reserveResources] Failed to append ID. As it has been referenced before assignment"
              	            logger.error("Attempting to append the ID when it has not been assigned yet")

                          # delete flavor
                          deleteFlavor(name)
        
        #print "before url creation"
        #url = "http://"+IP_ADDR+":"+PORT_ADDR+"/method/verifyResources"
        #data = reply
        #print "reply before", reply
        #headers = {'Content-Type': 'application/json'}

        try:
            #print "before requests"
            #print "data before", reservation
            #r = requests.post(url, data, headers=headers)
            reply = checkResources(reservation)
            if "false" in reply:
                #print "found false"
                result = {"result":{}}
            else:
                #print "found true"
                result = {"result":reservation}
            #print "after requests"
            #result = r.text
        except Exception.message, e:
            response.status = 400
            error = {"message":e,"code":response.status}
            return error

        #print result
        #return result
        #result = {"result":reply}
        jsondata = json.dumps(result)
        return jsondata

    except Exception.message, e:
        response.status = 400
        if name:
            deleteFlavor(name)
        error = {"message":e,"code":response.status}
        return error
        logger.error(error)

    logger.info("Completed!")

# To be fixed with DELETE
@route('/method/releaseResources/<ID>', method='POST')
def releaseResources(ID):
    logger.info("Called")
    headers = {'X-Auth-Token': token_id}
    #print headers
    #print token_id    
    if str(token_id) not in str(headers):
    	raise AttributeError("N-Irm: [releaseResources/<ID>] Failure to assign headers. Possibly incorrect token_id")
    	logger.error("Failed to assign headers. Possible fault in token_id")
   
    r = requests.delete(public_url+'/servers/'+ID, headers=headers)
    return r
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

# To be fixed with DELETE
@route('/method/releaseResources/', method='POST')
@route('/method/releaseResources', method='POST')
def releaseResources():
    logger.info("Called")
    try:
    	reservations = json.load(request.body)
    except ValueError:
    	print "N-Irm [releaseResources] Attempting to load a non-existent payload, please enter desired layout"
    	print " "
    	logger.error("Payload was empty or incorrect. A payload must be present and correct")
    try:
        
        reply = deleteResources(reservations)
        if "DONE" in reply:
            return { "result": { } }

        else:
            return { "result": reply }
    #return r
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        return error
        logger.error(error)

    logger.info("Completed!")

# To be fixed with DELETE
@route('/method/releaseAllResources/', method='POST')
@route('/method/releaseAllResources', method='POST')
def releaseResources():
    logger.info("Called")
    try:
        reservations = getListInstances()
        #print reservations
    except ValueError:
        print "N-Irm [releaseResources] Attempting to load a non-existent payload, please enter desired layout"
        print " "
        logger.error("Payload was empty or incorrect. A payload must be present and correct")
    try:
        
        reply = deleteResources(reservations)
        #reply = {"DONE"}
        if "DONE" in reply:
            return { "result": { } }
        else:
            return { "result": reply }
    #return r

        if ID in req['Reservations'] is None:            	
            raise UnboundLocalError
    except UnboundLocalError:
        raise UnboundLocalError("N-Irm: [releaseResources] Payload may be missing. Or ID is missing or empty. Please check Payload!")
        return { "result": { } }


    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        return error
        logger.error(error)

    logger.info("Completed!")

@route('/method/calculateResourceCapacity/', method='POST')
@route('/method/calculateResourceCapacity', method='POST')
def calculateResourceCapacity():
    logger.info("Called")
    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'POST, HEAD')
    try:          
        # get the body request
        try:
           req = json.load(request.body)
        except ValueError:
           print "N-Irm: [calculateResourceCapacity] Attempting to load a non-existent payload, please enter desired layout"
           print ""
           logger.error("Payload was empty or incorrect. A payload must be present and correct")

        cores = 0
        mem = 0
        disk = 0
        
        # optional reserve
        if 'Reserve' in req:
		     for majorkey in req['Reserve']:
		        try:
		           if majorkey['Attributes'].has_key('Cores'):
		             cores = cores - majorkey['Attributes']['Cores']
		        except KeyError: 
		           print "N-Irm [calculateResourceCapacity] failed to assign totCores in 'Reserve'" 
		           logger.error("totCores could not be assigned within 'Reserve'")
		           pass
		        try:
		           if majorkey['Attributes'].has_key('Memory'):
		             mem = mem - majorkey['Attributes']['Memory']
		        except KeyError: 
		           print "N-Irm [calculateResourceCapacity] failed to assign totMem in 'Reserve'" 
		           logger.error("totMem could not be assigned within 'Reserve'")
		           pass
		        try:
		           if majorkey['Attributes'].has_key('Disk'):
		             disk = disk - majorkey['Attributes']['Disk']
		        except KeyError: 
		           print "N-Irm [calculateResourceCapacity] failed to assign totDisk in 'Reserve'" 
		           logger.error("totDisk could not be assigned within 'Reserve'")
		           pass
		        #try: 
		        #    if maxFreq < majorkey['Attributes']['Frequency']:
		        #        maxFreq = majorkey['Attributes']['Frequency']
		        #except KeyError: pass
		  # optional release     
        if 'Release' in req:
		     for majorkey in req['Release']:
		        try:
		           if majorkey['Attributes'].has_key('Cores'):
		             cores = cores + majorkey['Attributes']['Cores']
		        except KeyError: 
		        	  print "N-Irm [calculateResourceCapacity] failed to assign totCores in 'Release'"
		        	  logger.error("totCores could not be assigned within 'Release'")
		        	  pass
		        try:
		           if majorkey['Attributes'].has_key('Memory'):
		             mem = mem + majorkey['Attributes']['Memory']
		        except KeyError: 
		        	  print "N-Irm [calculateResourceCapacity] failed to assign totMem in 'Release'"
		        	  logger.error("totMem could not be assigned within 'Release'") 
		        	  pass
		        try:
		           if majorkey['Attributes'].has_key('Disk'):
		             disk = disk + majorkey['Attributes']['Disk']
		        except KeyError: 
		        	  print "N-Irm [calculateResourceCapacity] failed to assign totMem in 'Release'" 
		        	  logger.error("totMem could not be assigned within 'Release'")
		        	  pass
		        #try:
		        #    if maxFreq < majorkey['Attributes']['Frequency']:
		        #        maxFreq = majorkey['Attributes']['Frequency']
		        #except KeyError: pass
        try:
            rType = req['Resource']['Type']
        except AttributeError:
        	print "Failed to assign Resource type to 'rtype'"
        	logger.error("Unable to assign Resource type to 'rtype'")
        #print totCores,maxFreq,totMem,totDisk
        
        # only return the attributes included in 'Resource'
        attribs = req['Resource']['Attributes']
        # compute if we exceed capacity - if we do, we must return { }
        exceed_capacity = False
        if attribs.has_key("Cores"):
           attribs["Cores"] = attribs["Cores"] + cores
           exceed_capacity = attribs["Cores"] < 0           
        if (not exceed_capacity) and attribs.has_key("Memory"):
           attribs["Memory"] = attribs["Memory"] + mem          
           exceed_capacity = attribs["Memory"] < 0                       
        if (not exceed_capacity) and attribs.has_key("Disk"):
           attribs["Disk"] = attribs["Disk"] + disk
           exceed_capacity = attribs["Disk"] < 0                                    
        if exceed_capacity:
           reply = { }
        else:
           reply = {"Resource":{"Type":rType,"Attributes":attribs}}
        result = {"result":reply}
        jsondata = json.dumps(result)
        return jsondata
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        return error
        logger.error(error)   
    logger.info("Completed!")

@route('/method/calculateResourceAgg/', method='POST')
@route('/method/calculateResourceAgg', method='POST')
def calculateResourceAgg():
    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'POST, HEAD')
    logger.info("Called")
    try:
        try:
            # get the body request
            req = json.load(request.body)
        except ValueError: 
        	print 'N-Irm: [calculateResourceAgg] Attempting to load a non-existent payload, please enter desired layout'
        	print ' '
        	logger.error("Payload was empty or incorrect. A payload must be present and correct")
        # loop through all requested resources
        totCores = 0
        totMem = 0
        maxFreq = 0
        totDisk = 0
        rType = req['Resources'][0]['Type']
        #rType = 'machine' 

        for majorkey in req['Resources']:
           try: totCores = totCores + majorkey['Attributes']['Cores']
           except KeyError:
              print "N-Irm [calculateResourceAgg] failed to assign totCores in 'Resources'. Possible payload spelling error"
              logger.error("Failure to assign totCores within 'Resources. Potential spelling error'") 
              raise KeyError
           try: totMem = totMem + majorkey['Attributes']['Memory']
           except KeyError: 
              print "N-Irm [calculateResourceAgg] failed to assign totMem in 'Resources'. Possible payload spelling error" 
              logger.error("Failure to assign totMem within 'Resources. Potential spelling error'")               
              raise KeyError
           try: totDisk = totDisk + majorkey['Attributes']['Disk']
           except KeyError: 
              print "N-Irm [calculateResourceAgg] failed to assign totDisk in 'Resources'. Possible payload spelling error" 
              logger.error("Failure to assign totDisk within 'Resources. Potential spelling error'")
              raise KeyError
           try:
               if maxFreq < majorkey['Attributes']['Frequency']:
                   maxFreq = majorkey['Attributes']['Frequency']
           except KeyError: pass
        #print totCores,maxFreq,totMem,totDisk

        reply = {"Type":rType,"Attributes":{"Cores":totCores,"Frequency":maxFreq,"Memory":totMem,"Disk":totDisk}}
        result = {"result":reply}
        
        jsondata = json.dumps(result)
        return jsondata
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        return error
        logger.error(error)
    logger.info("Completed!")

def getifip(ifn):
    '''
Provided network interface returns IP adress to bind on
'''
    import socket, fcntl, struct
    sck = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(sck.fileno(), 0x8915, struct.pack('256s', ifn[:15]))[20:24])
    #return '131.254.16.173'

def startAPI(IP_ADDR,PORT_ADDR):
    # check if irm already running
    command = "ps -fe | grep irm-nova.py | grep python | grep -v grep"
    proccount = subprocess.check_output(command,shell=True).count('\n')
    proc = subprocess.check_output(command,shell=True)
    if proccount > 1:
        print "---Check if irm is already running. Connection error---"
        sys.exit(0)
    else:
        print"IRM API IP address:",IP_ADDR
        if CONFIG.get('CRS', 'ACTIVE') == "on":
            Thread(target=registerIRM).start()
            print 'Registration with CRS done'
        API_HOST=run(host=IP_ADDR, port=PORT_ADDR)
    return IP_ADDR

def init(novaapi,tenantname,username,password,interface):
    global os_api_url 
    os_api_url = "http://"+novaapi
    global token_id
    token_id = createToken(os_api_url, tenantname, username, password)
    global public_url
    public_url = getEndPoint(os_api_url, token_id)
    #print public_url
    global host_list
    host_list = loadHostList()
    global IP_ADDR
    IP_ADDR=getifip(interface)
    global CONFIG
    if 'CONFIG' not in globals():
        CONFIG = ConfigParser.RawConfigParser()
        CONFIG.read('irm.cfg') 
 
def default():
    INTERFACE = "eth0"
    print "No interface specified, using "+INTERFACE+" as default"
    PORT_ADDR = 5050
    print "No port specified, using "+str(PORT_ADDR)+" as default"
    NOVAAPI = getifip(INTERFACE)+":5000"
    print "No nova api specified, using "+NOVAAPI+" as default"
    TENANTNAME = "tenant"
    print "No tenantname specified, using "+TENANTNAME+" as default"
    USERNAME = "admin"
    print "No username specified, using "+USERNAME+" as default"
    PASSWORD = "password"
    print "No password specified, using "+PASSWORD+" as default"
    

def main():
    usage = "Usage: %prog [option] arg"
    #paragraph of help text to print after option help
    epilog= "Copyright 2014 SAP Ltd"
    #A paragraph of text giving a brief overview of your program
    description="""IRM is small api that enables the Cross Resource Scheduler (CRS) to talk to the nova API"""
    parser = optparse.OptionParser(usage=usage,epilog=epilog,description=description)
    
    parser.add_option('-v','--version', action='store_true', default=False,dest='version',help='show version information')
    #parser.add_option('-h','--help', action='store_true', default=False,dest='help',help='show help')
    parser.add_option('-i','--interface', action='store', type="string", default=False,dest='interface',help='network interface to start the API')
    parser.add_option('-p','--port', action='store', default=False,dest='port',help='port to start the API')
    parser.add_option('-a','--nova-api', action='store', default=False,dest='novaapi',help='nova api to connect to, format: <IP>:<PORT>')
    parser.add_option('-t','--tenantname', action='store', default=False,dest='tenantname',help='nova tenantname for the connenction to the API')
    parser.add_option('-u','--username', action='store', default=False,dest='username',help='nova username for the connenction to the API')
    parser.add_option('-w','--password', action='store', default=False,dest='password',help='nova password for the connenction to the API')
    parser.add_option('-c','--config', action='store', default=False,dest='config',help='config file to run the IRM-nova in daemon mode')

    options, args = parser.parse_args()
    #print options, args
    if options.version:
        #noExtraOptions(options, "version")
        VERSION = "0.1"
        #os.system("clear")
        text = '''
Copyright 2012-2013 SAP Ltd
'''
        print VERSION
        sys.exit(1)
    
    global PORT_ADDR 
    if options.config:
       global CONFIG
       CONFIG = ConfigParser.RawConfigParser()
       CONFIG.read(options.config)
       INTERFACE = CONFIG.get('main', 'IRM_INTERFACE')
       PORT_ADDR = CONFIG.get('main', 'IRM_PORT')
       NOVAAPI = CONFIG.get('main', 'NOVA_ENDPOINT')
       TENANTNAME = CONFIG.get('main', 'TENANT_NAME')
       USERNAME = CONFIG.get('main', 'USERNAME')
       PASSWORD = CONFIG.get('main', 'PASSWORD')
    else:
    
       if options.interface:
          INTERFACE = options.interface 
       else:
          INTERFACE = "eth0"
          print "No interface specified, using "+INTERFACE+" as default"

       if options.port:
          PORT_ADDR = options.port
       else:
          PORT_ADDR = 5050
          print "No port specified, using "+str(PORT_ADDR)+" as default"
 
       if options.novaapi:
          NOVAAPI = options.novaapi
       else:
          NOVAAPI = getifip(INTERFACE)+":5000"
          print "No nova api specified, using "+NOVAAPI+" as default"

       if options.tenantname:
          TENANTNAME = options.tenantname
       else:
          TENANTNAME = "tenant"
          print "No tenantname specified, using "+TENANTNAME+" as default"
    
       if options.username:
          USERNAME = options.username
       else:
          USERNAME = "admin"
          print "No username specified, using "+USERNAME+" as default"
    
       if options.password:
          PASSWORD = options.password
       else:
          PASSWORD = "password"
          print "No password specified, using "+PASSWORD+" as default"

    try:
       init(NOVAAPI,TENANTNAME,USERNAME,PASSWORD,INTERFACE)
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
    
