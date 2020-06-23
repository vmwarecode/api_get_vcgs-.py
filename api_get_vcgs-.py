#!/usr/bin/env/python
#
# api_edge_vcg.py
#
# A simple VCO API client to retrieve VCG list assigned to each edge
#
# author: Vladimir F de Sousa - vfrancadesou@vmware.com
# date: June 2020
#
# Use at your own risk
#
# please note that VMWare API and Support team - do not guarantee this samples
# It is provided - AS IS - i.e. while we are glad to answer questions about API usage
# and behavior generally speaking, VMware cannot and do not specifically support these scripts

import sys
import getpass
import requests
import json
import re
import math
import copy
import os
import time
from netaddr import IPAddress
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ApiException(Exception):
    pass

class VcoRequestManager(object):

    def __init__(self, hostname, verify_ssl=True):
        self._session = requests.Session()
        self._verify_ssl = verify_ssl
        self._root_url = self._get_root_url(hostname)
        self._portal_url = self._root_url + "/portal/"
        self._livepull_url = self._root_url + "/livepull/liveData/"
        self._seqno = 0

    def _get_root_url(self, hostname):
        """
        Translate VCO hostname to a root url for API calls
        """
        if hostname.startswith("http"):
            re.sub('http(s)?://', '', hostname)
        proto = "https://"
        return proto + hostname

    def authenticate(self, username, password, is_operator=True):
        """
        Authenticate to API - on success, a cookie is stored in the session
        """
        path = "/login/operatorLogin" if is_operator else "/login/enterpriseLogin"
        url = self._root_url + path
        data = { "username": username, "password": password }
        headers = { "Content-Type": "application/json" }
        r = self._session.post(url, headers=headers, data=json.dumps(data),
                               allow_redirects=False, verify=self._verify_ssl)

    def call_api(self, method, params):
        """
        Build and submit a request
        Returns method result as a Python dictionary
        """
        self._seqno += 1
        headers = { "Content-Type": "application/json" }
        method = self._clean_method_name(method)
        payload = { "jsonrpc": "2.0",
                    "id": self._seqno,
                    "method": method,
                    "params": params }

        if method in ("liveMode/readLiveData", "liveMode/requestLiveActions", "liveMode/clientExitLiveMode"):
            url = self._livepull_url
        else:
            url = self._portal_url

        r = self._session.post(url, headers=headers,
                               data=json.dumps(payload), verify=self._verify_ssl)

        response_dict = r.json()
        if "error" in response_dict:
            print(response_dict)
            raise ApiException(response_dict["error"]["message"])
        return response_dict["result"]

    def _clean_method_name(self, raw_name):
        """
        Ensure method name is properly formatted prior to initiating request
        """
        return raw_name.strip("/")


#get current time
current_time = time.strftime("%m.%d.%y.%H.%M", time.localtime())


#to run this script securely, add env variables in your OS
# to be used till machine is booted or only where the session is running.
# MAC OS: 
# export VCO_IP=10.123.16.79 ; export VCO_USER=lab@lab.com ; export VCO_PASS='Velocloud123!#'

print "Enter credentials and VCO"
vcoIP = raw_input("VCO: ")
targetUsername = raw_input("Username: ")
targetPassword = getpass.getpass("Password: ")

#print "Username: [%s], password [%s] vco [%s]" % (targetUsername, targetPassword, vcoIP)


#this script is suppose to be run by a non-operator/partner user
is_op=False

clientTarget = VcoRequestManager(vcoIP, verify_ssl=False)
clientTarget.authenticate(targetUsername, targetPassword, is_operator=is_op)


#GET enterprise Id for this enterprise user
entresp=clientTarget.call_api("enterpriseUser/getEnterpriseUser",{
  "id" : 0,
  "username": targetUsername
  })
targetEnterpriseId = entresp['enterpriseId']

#Get Edge List
resp = clientTarget.call_api("enterprise/getEnterpriseEdgeList",{
  "enterpriseId" : targetEnterpriseId,
  })
length = len(resp)
i = 0
while i < length:
    EdgeName=resp[i]['name']
    EdgeId=resp[i]['id']
    print ('Edge Name: '+str(EdgeName))
   
    ### GET GATEWAYS ASSOCIATED WITH EDGE
    resp2 = clientTarget.call_api("/edge/getEdgeConfigurationModules",{
      "edgeId" : EdgeId,
      "enterpriseId": targetEnterpriseId,
      "modules" : ["controlPlane"]   
      })
    respcontrol=resp2['controlPlane']['data']['gatewaySelection']
    #print json.dumps(resp-control)
    VCGname=respcontrol['primaryDetail']['name']
    VCGIP=respcontrol['primaryDetail']['ipAddress']
    VCG=VCGname+','+VCGIP
    secVCGname=respcontrol['secondaryDetail']['name']
    secVCGIP=respcontrol['secondaryDetail']['ipAddress']
    secVCG=secVCGname+','+secVCGIP
    superVCGname=respcontrol['superDetail']['name']
    superVCGIP=respcontrol['superDetail']['ipAddress']
    superVCG=superVCGname+','+superVCGIP
    AltVCGname=respcontrol['superAltDetail']['name']
    AltVCGIP=respcontrol['superAltDetail']['ipAddress']
    AltVCG=AltVCGname+','+AltVCGIP
    print 'primary VCG, '+VCG
    print 'secondary VCG, '+secVCG
    print 'super VCG, '+superVCG
    print 'super alternative VCG, '+AltVCG
    i += 1