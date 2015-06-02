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
#   - /method/verifyResources
#   - /method/reserveResources
#   - /method/releaseResources
#
#

import requests, json, pickle, sys, os, subprocess,optparse, time, thread, hresmon
import re
from bottle import route, run,response,request,re
import ConfigParser
from threading import Thread
import logging
import logging.handlers as handlers
from libnova import *
#from pudb import set_trace; set_trace()

#Config and format for logging messages
logger = logging.getLogger("Rotating Log")
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter(fmt='%(asctime)s.%(msecs)d - %(levelname)s: %(filename)s - %(funcName)s: %(message)s', datefmt='%d/%m/%Y %H:%M:%S')
handler = handlers.TimedRotatingFileHandler("n-irm.log",when="H",interval=24,backupCount=0)
## Logging format
handler.setFormatter(formatter)
logger.addHandler(handler)

with open("templates/json_getResourceTypes") as f:
    jsonGetResT = f.read()

jsonGetResT = json.loads(jsonGetResT)['Output']

######################################################## API ###################################################################

# To be fixed with GET
@route('/getAvailableResources/', method='GET')
@route('/getAvailableResources', method='GET')
def getAvailableResources(): 
    logger.info("Called")

    try:        
        option = "Resources"   
        resources = createListAvailableResources(host_list,public_url,token_id,option) 
        r = {"result":resources}       

        result = json.dumps(r)
        #print getImageUUIDbyName("conpaas")
        #print getNetUUIDbyName("private")
                     
    except Exception.message, e:
       response.status = 400
       error = {"message":e,"code":response.status}
       return error
       logger.error(error)
    
    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'GET, HEAD') 

    logger.info("Completed")   
    return result
    
# To be fixed with GET
@route('/getResourceTypes/', method='GET')
@route('/getResourceTypes', method='GET')
def getResourceTypes():
    logger.info("Called")
    try:
        #data = createListAvailableResources(host_list,public_url,token_id)
        types = {"Types":[]}
        #data = {"Type":"Machine","Attributes":{"Cores":{"Description":"Number of cores","DataType":"int"},"Frequency":{"Description":"Processor frequency","DataType":"double"},"Memory":{"Description":"Amount of RAM","DataType":"int"},"Disk":{"Description":"Disk capacity","DataType":"int"},"Image":{"Description":"Image name","DataType":"string"},"UserData":{"Description":"User custom data","DataType":"string"}}}
        types["Types"].append(jsonGetResT)
               
        result = {"result":types}
        r = json.dumps(result)
        
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        return error
        logger.error(error)
    
    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'GET, HEAD') 
    
    if r:
        return r
    else:
        return None
    logger.info("Completed!")


# To be fixed with GET
@route('/verifyResources/', method='POST')
@route('/verifyResources', method='POST')
def verifyResources():
    logger.info("Called")
    try:
        #print ID
        req = json.load(request.body)
    except ValueError as e:
        print e
        print "N-Irm: [verifyResources] Attempting to load a non-existent payload, please enter desired payload"   
        print " "
        logger.error("Payload was empty. A payload must be present")
    
   
    #print "in verifyResources"
   # print reply
    #network = getNetworks()[0]
    #print network
    #print "===> NETWORKS:", getNetworks()
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
        #jsondata = json.dumps(result)
        return result
    
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        return error
        logger.error(error)

    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'POST, HEAD') 

    logger.info("Completed!")

@route('/reserveResources/', method='POST')
@route('/reserveResources', method='POST')
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
        h_list = getHosts()
        #print h_list

        for resource in req['Resources']:
           #print resource
           # load values
           IP = resource['IP']
           #print "Image", resource['Image']
           if 'Image' in resource['Attributes']:
               image = getImageUUIDbyName(resource['Attributes']['Image'])
           else:
               if CONFIG.has_option('CRS','IMAGE_NAME'):
                   image = getImageUUIDbyName(CONFIG.get('CRS', 'IMAGE_NAME'))
           #print "Image after", image
           user_data = ''
           if 'UserData' in resource['Attributes']:
               user_data = resource['Attributes']['UserData']

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
           
           Monitor = ""
           if 'Monitor' in resource['Attributes']:
               Monitor = resource['Attributes']['Monitor']

           hostName = ""
          
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
                          createFlavor(name,vcpu,memory,disk)
                          headers = {'content-type': 'application/json','X-Auth-Token': token_id}
                          # build body for nova api
                          dobj = {"server" : {\
                                      "name" : name,\
                                      "imageRef" : image, \
                                      "flavorRef" : name,\
                                      "min_count": 1,\
                                      "max_count": 1,\
                                      "user_data": user_data,\
                                      "availability_zone":host}}
                          if CONFIG.has_option('network', 'NET_ID'):
                            UUID = getNetUUIDbyName(CONFIG.get('network', 'NET_ID'))
                            dobj["server"]["networks"] = [ { "uuid": UUID } ]
                            #print "getting net UUID"
                          elif CONFIG.has_option('network', 'UUID'):
                            dobj["server"]["networks"] = [ { "uuid": CONFIG.get('network', 'UUID') } ]
                             
                          #print dobj
                                                                                      
                          data = json.dumps(dobj)
                          #print "data before creating instance: ", data
                          #print "Creating instance number "+str(i+1)+", name "+name
                          print "Creating instance "+name
                          #r = requests.post(public_url+'/servers', data, headers=headers)
                          r = createResources(data)
                          
                          #print "====> ", str(r.json())
                          #print r.json()
                          try:
                            ID = r.json()['server']['id']
                            if Monitor:
                                createMonitorInstance(ID,IP,hostName,Monitor)
                            #print r.json()
                          except KeyError, msg:
                            print r.json()
                            logger.error(r.json())
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
@route('/releaseResources/<ID>', method='DELETE')
def releaseResources(ID):
    logger.info("Called")
    headers = {'X-Auth-Token': token_id}
    #print headers
    #print token_id    
    if str(token_id) not in str(headers):
    	raise AttributeError("N-Irm: [releaseResources/<ID>] Failure to assign headers. Possibly incorrect token_id")
    	logger.error("Failed to assign headers. Possible fault in token_id")
   
    r = requests.delete(public_url+'/servers/'+ID, headers=headers)
    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'DELETE, HEAD') 

    return r
    logger.info("Completed!")

# To be fixed with DELETE
@route('/releaseResources/', method='DELETE')
@route('/releaseResources', method='DELETE')
def releaseResources():
    logger.info("Called")
    try:
    	reservations = json.load(request.body)
    except ValueError:
    	print "N-Irm [releaseResources] Attempting to load a non-existent payload, please enter desired layout"
    	print " "
    	logger.error("Payload was empty or incorrect. A payload must be present and correct")
    try:
        destroyMonitoringInstance(reservations)
        print reservations
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
@route('/releaseAllResources/', method='DELETE')
@route('/releaseAllResources', method='DELETE')
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
        destroyMonitoringInstance(reservations)
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
    
    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'DELETE, HEAD') 

    logger.info("Completed!")

@route('/calculateResourceCapacity/', method='POST')
@route('/calculateResourceCapacity', method='POST')
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
           print "N-Irm: [calculateResourceCapacity] Attempting to load a non-existent payload, please enter desired layout\n"
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


@route('/getMetrics/', method='POST')
@route('/getMetrics', method='POST')
def getMetrics():
    logger.info("Called")
    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'POST, HEAD')
    try:          
        # get the body request
        try:
           req = json.load(request.body)
           print req
           r = hresmon.getResourceValueStore(req)
           return r
        except ValueError:
           print "N-Irm: [calculateResourceCapacity] Attempting to load a non-existent payload, please enter desired layout\n"
           logger.error("Payload was empty or incorrect. A payload must be present and correct")

    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        return error
        logger.error(error)   
    logger.info("Completed!")

# @route('/method/calculateResourceAgg/', method='POST')
# @route('/method/calculateResourceAgg', method='POST')
# def calculateResourceAgg():
#     response.set_header('Content-Type', 'application/json')
#     response.set_header('Accept', '*/*')
#     response.set_header('Allow', 'POST, HEAD')
#     logger.info("Called")
#     try:
#         try:
#             # get the body request
#             req = json.load(request.body)
#         except ValueError: 
#         	print 'N-Irm: [calculateResourceAgg] Attempting to load a non-existent payload, please enter desired layout'
#         	print ' '
#         	logger.error("Payload was empty or incorrect. A payload must be present and correct")
#         # loop through all requested resources
#         totCores = 0
#         totMem = 0
#         maxFreq = 0
#         totDisk = 0
#         rType = req['Resources'][0]['Type']
#         #rType = 'machine' 

#         for majorkey in req['Resources']:
#            try: totCores = totCores + majorkey['Attributes']['Cores']
#            except KeyError:
#               print "N-Irm [calculateResourceAgg] failed to assign totCores in 'Resources'. Possible payload spelling error"
#               logger.error("Failure to assign totCores within 'Resources. Potential spelling error'") 
#               raise KeyError
#            try: totMem = totMem + majorkey['Attributes']['Memory']
#            except KeyError: 
#               print "N-Irm [calculateResourceAgg] failed to assign totMem in 'Resources'. Possible payload spelling error" 
#               logger.error("Failure to assign totMem within 'Resources. Potential spelling error'")               
#               raise KeyError
#            try: totDisk = totDisk + majorkey['Attributes']['Disk']
#            except KeyError: 
#               print "N-Irm [calculateResourceAgg] failed to assign totDisk in 'Resources'. Possible payload spelling error" 
#               logger.error("Failure to assign totDisk within 'Resources. Potential spelling error'")
#               raise KeyError
#            try:
#                if maxFreq < majorkey['Attributes']['Frequency']:
#                    maxFreq = majorkey['Attributes']['Frequency']
#            except KeyError: pass
#         #print totCores,maxFreq,totMem,totDisk

#         reply = {"Type":rType,"Attributes":{"Cores":totCores,"Frequency":maxFreq,"Memory":totMem,"Disk":totDisk}}
#         result = {"result":reply}
        
#         jsondata = json.dumps(result)
#         return jsondata
#     except Exception.message, e:
#         response.status = 400
#         error = {"message":e,"code":response.status}
#         return error
#         logger.error(error)
#     logger.info("Completed!")

################################################################# End API #######################################################################

def createMonitorInstance(uuid,IP,host,template):
    logger.info("Called")
    print "In monitorInstance"
    itype = getInstanceType(host)
    print host,itype

    print METRICS

    #template = ""

    #if itype == "QEMU":
    #    template = "testJsonAgentRequestVM"
    #elif itype == "docker":
    #    template = "testJsonAgentRequestContainer"

    if template != "":
        #with open (template, "r") as myfile:
        #    data=myfile.read()

        # update uuid in template with current value
        print "INITIAL TEMPLATE",template
        #r = json.loads(template)
        #r["uuid"] = uuid
        template.update(METRICS)
        template['uuid'] = uuid

        if itype == "QEMU":
            template['instanceType'] = "vm"
            print "itype",itype
        if itype == "docker":
            template['instanceType'] = "container"
            print "itype",itype

        data = json.dumps(template)
        print "UPDATED TEMPLATE",template
        print "data",data


        hresmon.addResourceStatus(uuid,IP,data,"NEW")
    else:
        print "No hypervisor type found"

def destroyMonitoringInstance(reservations):
    logger.info("Called")
    print "In destroyMonitoringInstance"
    print "reservations",reservations
    for ID in reservations['Reservations']:
        print "uuid",ID
        r = hresmon.destroyAgent(ID)
    #print r


def registerIRM():
    logger.info("Called")
    logger.info( "ip:%s , port:%s, crs: %s" % (IP_ADDR, PORT_ADDR, CONFIG.get('CRS', 'CRS_URL')))
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
    
    global CONFIG
    if 'CONFIG' not in globals():
      CONFIG = ConfigParser.RawConfigParser()
      CONFIG.read('irm.cfg')
    
    global IP_ADDR
    if CONFIG.has_option('main', 'IRM_ADDRESS') and CONFIG.get('main', 'IRM_ADDRESS') != "":
        IP_ADDR=CONFIG.get('main', 'IRM_ADDRESS')
    elif interface != "":
        IP_ADDR=getifip(interface)
    else:
        IP_ADDR="0.0.0.0"

    global METRICS
    if CONFIG.has_section('metrics'):
        mfile = CONFIG.get('metrics', 'METRICS')
        with open(mfile) as f:
            METRICS = json.load(f)
      
 
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
    epilog= "Copyright 2015 SAP Ltd"
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
        VERSION = "0.2"
        #os.system("clear")
        text = '''
Copyright 2014-2015 SAP Ltd
'''
        print VERSION
        sys.exit(1)
    
    global PORT_ADDR 
    if options.config:
       global CONFIG
       CONFIG = ConfigParser.RawConfigParser()
       CONFIG.read(options.config)

       print options.config
       
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
    
