#!/usr/bin/env python

import requests, json, optparse, time, ast

with open("./json_reserveResources") as f:
    jsonReserveRes = f.read()

with open("./json_calculateResourceCapacity") as f:
    jsonCalcResCap = f.read()

with open("./json_calculateResourceAgg") as f:
    jsonCalcResAgg = f.read()

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
    return False
  return True

# currently this is just using POST, but should be updated with more verbs once the changes are done to the API
def apiTest(url,data=None):
    headers = {'Content-Type': 'application/json'}

    try:
        r = requests.post(url, data, headers=headers)
        result = r.text
    except Exception.message, e:
       response.status = 400
       error = {"message":e,"code":response.status}
       return error

    return result

apiList=["/method/getResourceTypes","/method/getResourceTypes","/method/calculateResourceCapacity","/method/calculateResourceAgg","/method/reserveResources","/method/verifyResources","/method/releaseResources"]


def testAPI():
    for api in apiList:
        url = irm_nova_url+api
        error = None
    
        try:
            if "reserveResources" in api:
                response = apiTest(url,jsonReserveRes)
            elif "verifyResources" in api:
                decoded = json.loads(response)['result']
                response = apiTest(url,json.dumps(decoded))
            elif "releaseResources" in api:
                # need to wait to give time the spawned instance to be active before deleting it
                time.sleep(5)
                response = apiTest(url,json.dumps(decoded))
            elif "calculateResourceCapacity" in api:
                response = apiTest(url,jsonCalcResCap)
            elif "calculateResourceAgg" in api:
                response = apiTest(url,jsonCalcResAgg)
            else:
                response = apiTest(url)
        except Exception.message, e:
            response.status = 400
            error = {"message":e,"code":response.status}

        if is_json(response) and error == None:
            PASSED = "PASSED"
        else:
            PASSED = "FAILED"
    
        print "API call",api,PASSED

testAPI()


