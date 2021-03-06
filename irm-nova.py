#!/usr/bin/env python
# Description
#
#
#
#
# Status
# - all APIs are implemented and seem to be working
#
#
#
# How it works
# - check the help
#    - ./irm-nova.py -h
#    - configuration file:
#       - irm-*.cfg
# - start the API
#    - e.g. ./irm-nova.py -a 192.168.56.108:5000 -t admin -u admin -w password -i eth0 -p 8888
#    - e.g. ./irm-nova.py -c irm.cfg
#    - it can also be started through supervisor (the startup command has to be added to supervisor.conf file)
#         - supervisord -c ./supervisord.conf
#
# - test
#    - unitTest
#       - cd tests
#       - ./test_irm-nova.py -i <irm-nova IP> -p <irm-nova PORT>
#    - use any rest client (e.g. RESTClient for firefox) to make calls to the API
#
# - available APIs
#   - /method/getResources
#   - /method/getAllocSpec
#   - /method/calculateCapacity
#   - /method/checkReservation
#   - /method/createReservation
#   - /method/releaseReservation
#   - /method/releaseAllReservations
#
#

import requests, json, pickle, sys, os, subprocess,optparse, time, thread, hresmon
import re
from bottle import route, run,response,request,re
import ConfigParser
from threading import Thread, Timer
import logging
import logging.handlers as handlers
import libnova
from libnova import *
import copy


#from pudb import set_trace; set_trace()

def createLogger():
    global logger
    #Config and format for logging messages
    logger = logging.getLogger("Rotating Log")
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(fmt='%(asctime)s.%(msecs)d - %(levelname)s: %(filename)s - %(funcName)s: %(message)s', datefmt='%d/%m/%Y %H:%M:%S')
    handler = handlers.TimedRotatingFileHandler("n-irm.log",when="H",interval=24,backupCount=0)
    ## Logging format
    handler.setFormatter(formatter)
    if not logger.handlers:
        logger.addHandler(handler)

######################################################## API ###################################################################

@route('/getResources/', method='GET')
@route('/getResources', method='GET')
def getResources(): 
    logger.info("Called")

    try:        
        option = "Resources"   
        resources = createListAvailableResources(public_url,token_id,option) 
        r = {"result":resources}       
        result = json.dumps(r)
      
                     
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        logger.error(error)
        return { "error": error }
    
    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'GET, HEAD') 

    logger.info("Resources result: "+result)
    logger.info("Completed")   
    return result
    
# To be fixed with GET
@route('/getAllocSpec/', method='GET')
@route('/getAllocSpec', method='GET')
def getAllocSpec():
    logger.info("Called")
    try:
        with open("templates/json_getAllocSpec") as f:
            jsonGetResT = f.read()

        jsonGetResT = json.loads(jsonGetResT)['Output']
        r = {"result":jsonGetResT}
        result = json.dumps(r)
        
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        logger.error(error)
        return { "error": error }
    
    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'GET, HEAD') 
    
    logger.info(r)
    logger.info("Completed!")
    if result:
        return result
    else:
        return None

# To be fixed with GET
@route('/checkReservation/', method='POST')
@route('/checkReservation', method='POST')
def checkReservation():
    logger.info("Called")
    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'POST, HEAD') 

    try:
        req = json.load(request.body)
        logger.info("Check Reservation for: "+json.dumps(req))
        reply = checkResources(req)
        result = {"result":reply}

        for ID in req['ReservationID']:
            monitAgentStatus = "NEW"
            while monitAgentStatus =="NEW" and "NoneType" not in str(monitAgentStatus):
                monitAgentStatus = hresmon.checkResourceStatus(ID)
                print "monitAgentStatus",monitAgentStatus
    
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        logger.error(error)
        return { "error": error }
    except ValueError as e:
        print e
        print "N-Irm: [verifyResources] Attempting to load a non-existent payload, please enter desired payload\n"   
        logger.error("Payload was empty. A payload must be present")

    logger.info("Checked Reservation: "+json.dumps(result))
    logger.info("Completed!")
    if result:
        return result
    else:
        return None

########## create/associate Public IP to instance
publicIPs = {}
def createPublicIPs(instances):
    global publicIPs
    logger.info("Called")

    for instance in instances:
        headers = {'content-type': 'application/json','X-Auth-Token': token_id}
        try:
            instance_id = instance[0]
            instance_ip = instance[1]
            
            if type(instance_ip) == unicode:
               instance_ip = str(instance_ip)
            
            IP = None
            resp = None
            if (type(instance_ip) == int) or (type(instance_ip) == bool) or (type(instance_ip) == str and instance_ip.upper() == "TRUE"):           
                r = requests.post(public_url+'/os-floating-ips', json.dumps({'pool': 'public'}), headers=headers)
                if r.status_code == 200:
                    resp = r.json()["floating_ip"]
                    IP = resp["ip"]
                    if ("id" in resp) and ("ip" in resp):
                       publicIPs[instance] = { "id":  resp["id"], "ip": resp["ip"] }
                    
            elif type(instance_ip) == str:
                IP = instance_ip         
            
            if IP != None:   
                r2 = requests.post(public_url+'/servers/%s/action' % instance_id , json.dumps(
                                     {'addFloatingIp': {'address': IP}}), headers=headers)
       
        except Exception as e:
            error = {"message":str(e),"code":400}
            logger.error(error)
            return error
        
    logger.info("Completed!")

def deletePublicIPs(instances):
    global publicIPs
    logger.info("Called")
    
    for instance in instances:   
        headers = {'content-type': 'application/json','X-Auth-Token': token_id}
        try:
           if instance in copy.copy(publicIPs):
              ID = publicIPs[instance]["id"]
              r2 = requests.delete(public_url+'/os-floating-ips/%s' % str(ID), headers=headers)
              del publicIPs[instance]
           
        except Exception as e:
           error = {"message":str(e),"code":400}
           print "error: ", error
           logger.error(error)
           return error
        
    logger.info("Completed!")
           
############################

@route('/createReservation/', method='POST')
@route('/createReservation', method='POST')
def createReservation():
    logger.info("Called")
    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'POST, HEAD')
    try:
        try:
            req = json.load(request.body)
            logger.info("Create Reservation for: "+json.dumps(req))
        except ValueError:
        	print "N-Irm [reserveResources] Attempting to load a non-existent payload please enter desired payload\n"
        	logger.error("Payload was empty or incorrect. A payload must be present and correct")

        cleanFlavors()
        reservation = {"ReservationID":[]}
        # loop through all requested resources
        name = ""
        h_list = getHosts()
        Monitor = ""
        public_ip_reqs = []
        
        cattribs = {} # cattribs has the common attributes across all requests
                      # used to substitute metric commands if necessary
        if 'Monitor' in req:
            Monitor = req['Monitor']
            req_machines = [ x['Attributes'] for x in req['Allocation'] if x['Type'] == "Machine" ]
            n = len(req_machines)
            if n > 0:
               cattribs = req_machines[0]
               for i in range(1,n):
                  R = req_machines[i]
                  cattribs = {x:y  for (x,y) in cattribs.items() if x in R and R[x] == y} 
            else:
               cattribs = {}
            #print "MONITOR section",Monitor

        for resource in req['Allocation']:
            try:
                if 'Type' not in resource or resource['Type'] != 'Machine':
                   msg = "Type not found, or invalid type found in request!"
                   raise Exception                  
                if 'ID' not in resource:
                   msg = "ID not found in allocation request!"
                   raise Exception            
                ID = resource['ID']

                if 'Image' in resource['Attributes']:
                    image = getImageUUIDbyName(resource['Attributes']['Image'])
                    #print image
                    if image == "Image Not Found":
                        msg = "Image Not Found"
                        raise Exception
                elif CONFIG.has_option('CRS','IMAGE_NAME'):
                    image = getImageUUIDbyName(CONFIG.get('CRS', 'IMAGE_NAME'))
                #print "Image after", image
                user_data = ''
                securityGroups = ''
                
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
                if 'securityGroups' in resource['Attributes']:
                    securityGroups = resource['Attributes']['securityGroups']
                elif CONFIG.has_option('main','SECURITYGROUP'):
                    securityGroups = CONFIG.get('main', 'SECURITYGROUP')

            except Exception:
                response.status = 500
                error = {"message":msg,"code":response.status}
                logger.error(error)
                return { "error": error }

            try:
                if ID in h_list:
                    novah = ID
                    # build host for availability_zone option to target specific host
     
                    host = "nova:"+novah
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
                                "security_groups": [{"name": securityGroups}],\
                                "availability_zone":host}}
     
                    if CONFIG.has_option('network', 'NET_ID'):
                        try:
                            UUID = getNetUUIDbyName(CONFIG.get('network', 'NET_ID'))
                            print "UUID",UUID
                            if "not Found" in UUID:
                                raise ValueError(UUID)

                            # sub = resource['Attributes'].get('Subnet')
                            # if sub:
                            #     userSubnetName = resource['Attributes']['Subnet']
                            #     userSubnetUUID = getSubnetUUIDbyName(userSubnetName)
                            #     mgtSubnetUUID = getMGTSubnetByNetUUID(UUID,userSubnetUUID)
                            #     #print "mgtSubnetUUID",mgtSubnetUUID
                            #     portName = "HARNESSPORT-"+createRandomID(6)
                            #     portID = createPort(UUID,mgtSubnetUUID,userSubnetUUID,portName)
                            #     dobj["server"]["networks"] = [{"port": portID}]
                            # else:
                            #     dobj["server"]["networks"] = [{"uuid":UUID}]

                        except ValueError,e:
                            response.status = 447
                            error = {"message":str(e),"code":response.status}
                            logger.error(error)
                            return { "error": error }
                    elif CONFIG.has_option('network', 'UUID'):
                        UUID = CONFIG.has_option('network', 'UUID')
                    
                    sub = resource['Attributes'].get('Subnet')
                    if sub:
                        userSubnetName = sub
                        userSubnetUUID = getSubnetUUIDbyName(userSubnetName)
                        mgtSubnetUUID = getMGTSubnetByNetUUID(UUID,userSubnetUUID)
                        portName = "HARNESSPORT-"+createRandomID(6)
                        portID = createPort(UUID,mgtSubnetUUID,userSubnetUUID,portName)
                        if "message" in portID:
                           raise ValueError(portID)                           
                        dobj["server"]["networks"] = [{"port": portID}]
                    else:
                        dobj["server"]["networks"] = [{"uuid": UUID}]
                                                                              
                    data = json.dumps(dobj)
                    print "Creating instance "+name 

                    r = createResources(data)
                    
                    serverID = r.json()['server']['id']
                    # store requests
                    if 'PublicIP' in resource['Attributes']:
                       public_ip_reqs.append((serverID, resource['Attributes']['PublicIP']))
 
                    try:
                        if Monitor:
                            createMonitorInstance(serverID,novah,Monitor, cattribs)
                    
                        reservation["ReservationID"].append(serverID)
                    except UnboundLocalError:
                        print "N-Irm [reserveResources] Failed to append ID. As it has been referenced before assignment"
                        logger.error("Attempting to append the ID when it has not been assigned yet\n")
                    except KeyError, msg:
                        print r.json()
                        logger.error(r.json())
                    # delete flavor
                    deleteFlavor(name)
                    #break
                else:
                    msg = "ID: "+ID+" not correct"
                    raise ValueError(msg)
            except ValueError, e:
                error = {"message":str(e),"code":444}
                return { "error": error }

        try:
            reply = checkResources(reservation)

            if "false" in reply:
                #print "found false"
                result = {"result":{}}
            elif "Empty" in reply:
                msg = "No reservation made. Check your request"
                raise ValueError(msg)
            else:
                createPublicIPs(public_ip_reqs)
                result = {"result":reservation}
        except Exception.message, e:
            response.status = 400
            error = {"message":e,"code":response.status}
            logger.error(error)
            return { "error": error }
        except ValueError, e:
                response.status = 445
                error = {"message":str(e),"code":response.status}
                logger.error(error)
                return { "error": error }

        jsondata = json.dumps(result)
        logger.info("Created Reservation: "+jsondata)
        logger.info("Completed!")
        return jsondata

    except Exception.message, e:
        response.status = 446
        if name:
            deleteFlavor(name)
        error = {"message":e,"code":response.status}
        logger.error(error)
        return { "error": error }


# To be fixed with DELETE
@route('/releaseResources/<ID>', method='DELETE')
def releaseResources(ID):
    logger.info("Called")
    headers = {'X-Auth-Token': token_id}
    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'DELETE, HEAD') 
    
    if str(token_id) not in str(headers):
    	raise AttributeError("N-Irm: [releaseResources/<ID>] Failure to assign headers. Possibly incorrect token_id")
    	logger.error("Failed to assign headers. Possible fault in token_id")
   
    r = requests.delete(public_url+'/servers/'+ID, headers=headers)
    logger.info("Completed!")
    return r

# To be fixed with DELETE
@route('/releaseReservation/', method='DELETE')
@route('/releaseReservation', method='DELETE')
def releaseReservation():
    logger.info("Called")
    try:
    	reservations = json.load(request.body)
        logger.info("Release reservation: "+json.dumps(reservations))
    except ValueError:
    	print "N-Irm [releaseResources] Attempting to load a non-existent payload, please enter desired layout\n"
    	logger.error("Payload was empty or incorrect. A payload must be present and correct")
    try:
        destroyMonitoringInstance(reservations)
        deletePublicIPs(reservations['ReservationID'])
        reply = deleteResources(reservations)
        logger.info("Completed!")
        return { "result": {} }
        
        '''
        if "DONE" in reply:
            return { "result": { } }
        else:
            return { "result": reply }
        '''    
    #return r
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        logger.error(error)
        return { "error": error }

# To be fixed with DELETE
@route('/releaseAllReservations/', method='DELETE')
@route('/releaseAllReservations', method='DELETE')
def releaseAllReservations():
    global publicIPs
    logger.info("Called")
    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'DELETE, HEAD')

    try:
        deletePublicIPs(publicIPs.keys())
        reservations = getListInstances()

        logger.info("Release reservations: "+json.dumps(reservations))
        #print "reservations",reservations
    except ValueError:
        print "N-Irm [releaseResources] Attempting to load a non-existent payload, please enter desired layout\n"
        logger.error("Payload was empty or incorrect. A payload must be present and correct")
    try:
        if reservations['ReservationID']:
            destroyMonitoringInstance(reservations)
            reply = deleteResources(reservations)
        else:
            reply = "No reservations to release"
        
        logger.info("Completed!")
        
        return { "result": {} }
        '''
        if "DONE" in reply:
            return { "result": { } }
        else:
            return { "result": reply }
        '''
        
        if ID in req['ReservationID'] is None:            	
            raise UnboundLocalError
    except UnboundLocalError:
        raise UnboundLocalError("N-Irm: [releaseResources] Payload may be missing. Or ID is missing or empty. Please check Payload!")
        return { "result": { } }

    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        logger.error(error)
        return { "error": error }

@route('/calculateCapacity/', method='POST')
@route('/calculateCapacity', method='POST')
def calculateCapacity():
    logger.info("Called")
    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'POST, HEAD')
    try:          
        # get the body request
        try:
            req = json.load(request.body)
            logger.info("Calculate Capacity: "+json.dumps(req))

        except ValueError:
            print "N-Irm: [calculateResourceCapacity] Attempting to load a non-existent payload, please enter desired layout\n"
            logger.error("Payload was empty or incorrect. A payload must be present and correct")

        cores = 0
        mem = 0
        disk = 0
        
        # optional reserve
        if 'Allocation' in req:
		     for majorkey in req['Allocation']:
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

        try:
            rType = req['Resource']['Type']
        except AttributeError:
        	print "Failed to assign Resource type to 'rtype'"
        	logger.error("Unable to assign Resource type to 'rtype'")
        
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
            reply = "Allocation cannot be satisfied"
            result = {"result": {} }
        else:
            reply = {"Resource":{"Type":rType,"Attributes":attribs}}
            result = {"result":reply}
        
        jsondata = json.dumps(result)
        logger.info("Completed!")
        return jsondata
    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        logger.error(error)
        return { "error": error }   


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
            logger.info("getMetrics for: "+json.dumps(req))
            #print "IN GETMETRICS, REQUEST",req
            #print "METRICS file",METRICS
            #derivedMetrics = None
            # nlines = req['lines']
            # if nlines != "all":
            #     try:
            #         nl = int(nlines)
            #         #if 'derived' in (METRICS['container']) and req['format'] == "derived":
            #         #    derivedMetrics = METRICS['container']['derived']
            #     except ValueError:
            #         response.status = 400
            #         error = {"message":"ValueError: "+nlines,"code":response.status}
            #         return { "error": error }
            #         logger.error(error)
            # else:
            #     try:
            #         if req['format'] == "derived":
            #             raise ValueError
            #     except ValueError:
            #         response.status = 400
            #         e = nlines + " and " + req['format'] + " bad combination, cannot be in the same request"
            #         error = {"message":"ValueError: "+e,"code":response.status}
            #         return { "error": error }
            #         logger.error(error)

            #r = hresmon.getResourceValueStore(req,derivedMetrics)
            res = hresmon.getResourceValueStore(req)
            
            if "message" in res:
                raise ValueError(res['message'])

            logger.info("Completed!")
            return {"result": res }
        except ValueError,e:
            msg = "N-Irm: Payload was empty or incorrect. A payload must be present and correct\n"
            print msg
            #print e
            response.status = 400
            error = {"message":msg+str(e),"code":response.status}
            logger.error("Payload was empty or incorrect. A payload must be present and correct")
            return { "error": error }

    except Exception.message, e:
        response.status = 400
        error = {"message":e,"code":response.status}
        logger.error(error)
        return { "error": error }   

################################################################# End API #######################################################################

def createMonitorInstance(uuid,host,reqMetrics,cattribs={}):
    logger.info("Called")
    logger.info("Create monitor instance for "+uuid+" in host "+host)
    print "In monitorInstance"
    itype = getInstanceType(host)
    if DHCP_EXTENSION != "":
        fullhostname = host+"."+DHCP_EXTENSION
    else:
        fullhostname = host

    if reqMetrics != "":
        count = 0
        
        if itype == "QEMU":
            updMetrics = METRICS['vm']
            #print "len(updMetrics['metrics']:",len(updMetrics['metrics'])
            #template.update(METRICS['vm'])
            updMetrics = mergeRequestOptim(reqMetrics,updMetrics)
            updMetrics['instanceType'] = "vm"

        if itype == "docker":
            #template.update(METRICS['container'])
            updMetrics = METRICS['docker']
            updMetrics = mergeRequestOptim2(reqMetrics,updMetrics,cattribs)
            updMetrics['instanceType'] = "docker"

        if itype == "LXC":
            #template.update(METRICS['container'])
            updMetrics = METRICS['lxc']
            updMetrics = mergeRequestOptim(reqMetrics,updMetrics)
            updMetrics['instanceType'] = "lxc"
            updMetrics['instanceName'] = getInstanceName(uuid)
            #instanceName = getInstanceName(uuid)
            #print "I'm in createMonitorInstance",instanceName
            
        #print "itype",itype

        updMetrics['PollTime'] = reqMetrics['PollTime']
        updMetrics['uuid'] = uuid
        data = json.dumps(updMetrics)
        hresmon.addResourceStatus(uuid,fullhostname,data,"NEW")
    else:
        print "No hypervisor type found"
        logger.error("No hypervisor type found")

    logger.info("Completed!")


def mergeRequest(reqMetrics,updMetrics):
    count = 0
    while count < len(updMetrics['metrics']):
        count2 = 0
        found = False
        while count2 < len(reqMetrics['metrics']) and (found == False):
            #print "COMPARING:",updMetrics['metrics'][count]['name'],reqMetrics['metrics'][count2]['name']
            if updMetrics['metrics'][count]['name'] == reqMetrics['metrics'][count2]['name']:
                updMetrics['metrics'][count]['pollMulti'] = reqMetrics['metrics'][count2]['pollMulti']
                found = True
            else:
                count2 += 1
        count += 1
    return updMetrics

def mergeRequestOptim(reqMetrics,updMetrics):
    #count = 0
    for x in updMetrics['metrics']:
        z = next(y for y in reqMetrics['metrics'] if x['name'] == y['name'])
        #print "COMPARING:",x['name'],z['name']
        updMetrics['metrics'][updMetrics['metrics'].index(x)]['pollMulti'] = z['pollMulti']

    return updMetrics

def mergeRequestOptim2(reqMetrics,orgMetrics,cattribs):
    print ":::::::::>", cattribs
    updMetrics = {"metrics":{}}
    for key in reqMetrics['Machine']:
        if key in orgMetrics['metrics']: 
            org_metrics = orgMetrics['metrics'][key]
            cmd = org_metrics['command']
            for c in cattribs:
               cmd = cmd.replace('%'+c.upper(), str(cattribs[c]))

            updMetrics['metrics'][key] = copy.deepcopy(orgMetrics['metrics'][key])
            updMetrics['metrics'][key]['command'] = cmd
            updMetrics['metrics'][key].update(reqMetrics['Machine'][key])
    return updMetrics

def destroyMonitoringInstance(reservations):
    logger.info("Called")
    print "In destroyMonitoringInstance"
    for ID in reservations['ReservationID']:
        #print "uuid",ID
        logger.info("Destroying Agent: "+ID)
        r = hresmon.destroyAgent(ID)
    
    logger.info("Completed!")

def registerIRM():
    logger.info("Called")
    logger.info( "ip:%s , port:%s, crs: %s" % (IP_ADDR, PORT_ADDR, CONFIG.get('CRS', 'CRS_URL')))
    headers = {'content-type': 'application/json'}
    try:
       data = json.dumps(\
       {\
       #"Address":IP_ADDR,\
       "Port":PORT_ADDR,\
       "Name":"IRM-NOVA"\
       })
    except AttributeError:
        logger.error("Failed to json.dumps into data")
   
    # add here a check if that flavor name exists already and in that case return the correspondent ID
    # without trying to create a new one as it will fail
    r = requests.post(CONFIG.get('CRS', 'CRS_URL')+'/registerManager', data, headers=headers)
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
    logger.info("Called")
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
            logger.info("Registration with CRS done")
        API_HOST=run(host=IP_ADDR, port=PORT_ADDR)

    logger.info("Completed!")
    return IP_ADDR

def refresh_token():
   global CONFIG, os_api_url, token_id
   
   tenantname = CONFIG.get('main', 'TENANT_NAME')
   username = CONFIG.get('main', 'USERNAME')
   password = CONFIG.get('main', 'PASSWORD')
   
   print "requesting token..."
   token_id = createToken(os_api_url, tenantname, username, password)
   
   Timer(1200.0, refresh_token).start (); 
      
       
def init(novaapi,tenantname,username,password,interface):
    logger.info("Called")
    global os_api_url 
    os_api_url = "http://"+novaapi
    #global token_id
    #token_id = createToken(os_api_url, tenantname, username, password)
    refresh_token()
    
    global public_url
    global net_url
    [public_url,net_url] = getEndPoints(os_api_url, token_id)
    #print public_url
    #print net_url
    #global host_list
    #host_list = loadHostList()
    
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

    global DHCP_EXTENSION
    if CONFIG.has_option('main', 'DHCP_EXTENSION') and CONFIG.get('main', 'DHCP_EXTENSION') != "":
        DHCP_EXTENSION = CONFIG.get('main', 'DHCP_EXTENSION')
    else:
        DHCP_EXTENSION = ""

    global METRICS
    if CONFIG.has_section('metrics'):
        mfile = CONFIG.get('metrics', 'METRICS')
        with open(mfile) as f:
            METRICS = json.load(f)

    logger.info("Completed!")
      
 
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
    createLogger()
    libnova.createLogger()
    hresmon.createLogger()

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
    
    parser.add_option('-m', '--monitor', action="store_true", default=False, dest='monitor', help='autostart monitor')  

    options, args = parser.parse_args()
    
    if options.monitor:
       import subprocess
       LDIR=os.path.dirname(os.path.abspath(__file__))
       os.system("pkill -f hresmon")
       subprocess.Popen(['python', LDIR + '/hresmon.py'])    
    
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
       libnovaInit(options.config)

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
       logger.info("Initialization done")
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
    
