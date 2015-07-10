#!/usr/bin/env python

import requests, json, optparse, time, ast

with open("./json_createReservation") as f:
    jsonReserveRes = f.read()

with open("./json_calculateCapacity") as f:
    jsonCalcResCap = f.read()

#with open("./json_calculateResourceAgg") as f:
#    jsonCalcResAgg = f.read()

IP=""
PORT=""
parser = optparse.OptionParser()
parser.add_option('-p','--port', action='store', default=False, dest='port', help='IRM-nova port')
parser.add_option('-i','--IP', action='store', default=False, dest='ip', help='IRM-nova IP')

###
### assignment of options or defaults based on presence
###
options, args = parser.parse_args()
if options.port:
    PORT = options.port
else:
    PORT = '8888'
    print "No IRM-nova port specified, using "+PORT+" as default"
if options.ip:
    IP = options.ip
else:
    IP = "127.0.0.1"
    print "No IRM-nova IP specified, using "+IP+" as default"

irm_nova_url = "http://"+IP+":"+PORT

def is_json(myjson):
  try:
    json_object = json.loads(myjson)
  except ValueError, e:
    print "ValueError",e
    print "Response",myjson
    return False
  return True

# currently this is just using POST, but should be updated with more verbs once the changes are done to the API
def apiTest(url,verb="POST",data=None):
    headers = {'Content-Type': 'application/json'}

    try:
        r = requests.Response
        if "GET" in verb:
            r = requests.get(url, data=data, headers=headers)
        elif verb == "POST":
            r = requests.post(url, data, headers=headers)
        elif verb == "DELETE":
            r = requests.delete(url, data=data, headers=headers)
        result = r.text
        if r.raise_for_status():
            raise requests.exceptions.HTTPError("Erro in response status")
        #print "And you get an HTTPError:", e.message
        #error = {"message":e.message,"code":404}
        #return error
    except Exception.message, e:
        #response.status = 400
        error = {"message":e,"code":400}
        return error

    return result

apiList=["/getResources","/getAllocSpec","/calculateCapacity","/createReservation","/checkReservation","/getMetrics","/releaseReservation","/releaseAllReservations"]


def testAPI():
    for api in apiList:
        url = irm_nova_url+api
        error = None
        #print "api:",api
    
        try:
            if "createReservation" in api:
                response = apiTest(url,"POST",jsonReserveRes)
                #print "RESERVER TEST:",json.loads(response)['result']['Reservations']
                if not json.loads(response)['result']['ReservationID']:
                    error = "Data empty"
            elif "checkReservation" in api:
                decoded = json.loads(response)['result']
                response = apiTest(url,"POST",json.dumps(decoded))
                if not json.loads(response)['result']['Instances']:
                    error = "Data empty"
            elif "getMetrics" in api:
                #print "getMetrics test",decoded['ReservationID'][0]
                time.sleep(10)
                data = {"ReservationID":decoded['ReservationID'][0],"Entry":1}
                #print "getMetrics data:",data
                response = apiTest(url,"POST",json.dumps(data))
            elif "releaseReservation" in api:
                # need to wait to give time the spawned instance to be active before deleting it
                time.sleep(5)
                response = apiTest(url,"DELETE",json.dumps(decoded))
            elif "releaseAllReservations" in api:
                # Need to do another reservation to test this API
                #print "in releaseAllReservations"
                response = apiTest(irm_nova_url+"/createReservation","POST",jsonReserveRes)
                #decoded = json.loads(response)['result']
                #print decoded
                # need to wait to give time the spawned instance to be active before deleting it
                time.sleep(5)
                response = apiTest(url,"DELETE",None)
            elif "calculateCapacity" in api:
                data = json.loads(jsonCalcResCap)['Input']
                #print "json.loads(jsonCalcResCap)['Input']",data
                out = json.loads(jsonCalcResCap)['Output']
                #print "json.loads(jsonCalcResCap)['Output']",out

                response = apiTest(url,"POST",json.dumps(data))
                #print "calculateCapacity response",response

                res = json.loads(response)

                if res != out:
                    print "WARNING: BAD calculateCapacity Output"
                    error = "BAD"

#            elif "calculateResourceAgg" in api:
#                response = apiTest(url,"POST",jsonCalcResAgg)
            elif "getResources" or "getAllocSpec" in api:
                response = apiTest(url,"GET",None)
            else:
                #print "default api call"
                response = apiTest(url)
        except Exception.message, e:
            response.status = 400
            error = {"message":e,"code":response.status}
            pass
        except requests.exceptions.HTTPError as e:
            print e
            error = {"message":e.message,"code":404}

        if is_json(response) and error == None:
            STATUS = "PASSED"
        else:
            STATUS = "FAILED"
    
        print "API call",api,STATUS

testAPI()


