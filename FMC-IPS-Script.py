
import time  ## Time
import json  ##JAVA + API handler
import sys
import requests ##POSTMAN
#import queue
import getpass ## Password hide
import getch
import re


from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

####<<Function for a yes/no question via raw_input() and return their answer >>#####
####################################################################################
def query_yes_no(question, default="yes"):
    valid = {"yes":True,   "y":True,  "ye":True,
             "no":False,     "n":False}
    if default == None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "\
                             "(or 'y' or 'n').\n")

####<<Function for removing error info from list>>#####
#######################################################
def remove_error_info(d):
    if not isinstance(d, (dict, list)):
        return d
    if isinstance(d, list):
        return [remove_error_info(v) for v in d]
    return {k: remove_error_info(v) for k, v in d.items()
            if k not in {'metadata', 'links'}}

####<<Function to get new Token from REST API and returns the headers>>########
###############################################################################
def new_token(ipaddr,user1,pass1):
    url_start = "https://"
    headers = {
    'cache-control': "no-cache",
    'postman-token': "ff30c506-4739-9d4d-2e53-0dc7efc2036a"
    }
    r = None
    headers = {'Content-Type': 'application/json'}
    api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
    auth_url = url_start + ipaddr + api_auth_path
    try:
        r1 = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(user1,pass1), verify=False)
        auth_headers = r1.headers
        auth_token = auth_headers.get('X-auth-access-token', default=None)

        if auth_token == None:
          print("Authentication Token not found. Exiting...")
          sys.exit()
    except Exception as err:
      print ("Error in generating Authentication Token --> "+str(err))
      sys.exit()

    return auth_token


print ("==========================================")
print ("=                                        =")
print ("=         Cisco Firepower API            =")
print ("= Enabling IPS and Logging to ACP Script =")
print ("=                                        =")
print ("==========================================")
print ("=        Coded by:DTMDENNIS              =")
print ("==========================================")



url_start = "https://" ####<< start of URL to be Added to REST API URL >> ####
ipaddr = input("Enter your FMC IP address or hostname: ") ####<< Input FMC IP Address by user and store it in ipaddr >> ####
user1= input("Enter your FMC username: ") ####<< Input FMC username by user and store it in user1 >> ####
pass1= input("Enter your FMC password: ") ####<< Input FMC password by user and store it in pass1 >> ####
#pass1 = getpass.getpass("Enter your FMC password:") ####<< Input and hide FMC password by user and store it in pass1 >> ####
querystring = {"limit":"1000"} ####<< FMC Access-Control Max number of query per one Page >>####

####<< declear headers list with Postman token to use it in REST API Call>>####
headers = {
    'cache-control': "no-cache",
    'postman-token': "ff30c506-4739-9d4d-2e53-0dc7efc2036a"
    }

print ("Retrieving all Intrusion Policies ...")

#######################################################################
#######################################################################

headers['X-auth-access-token']= new_token(ipaddr,user1,pass1) #### << Function to get New Token >> #####


####<<Calling the IPS Rules , adding number for each rule and display them to user to choose one>>####
######################################################################################################
api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/intrusionpolicies"
url = url_start + ipaddr + api_path
if (url[-1] == '/'):
    url = url[:-1]
num_array = list()

try:
    r6 = requests.get(url, headers=headers,params=querystring, verify=False)
    status_code = r6.status_code
    resp = r6.text
    if (status_code == 200):
        print ("The current Intrusion Policies are: ")
        number=1
        json_resp6 = json.loads(resp)
        for i in range(len(json_resp6["items"])):
            num_array.append(json_resp6["items"][i]["name"])
            print ("%d. %s" % (number,json_resp6["items"][i]["name"]))
            number+=1

    else:
        r6.raise_for_status()
        print("Error occurred in --> "+resp)
except requests.exceptions.HTTPError as err:
    print ("Error in connection --> "+str(err))
finally:
    if r6 : r6.close()
####<<choose number of the IPS rule want to push>>####
######################################################
while True:
 choicenum = int(input ("Type the number of the IPS Policy for which you would like to apply: "))
 choicenum-=1
 if choicenum in range(len(num_array)):
  for i in range(len(num_array)):
    if choicenum == i:
      choice6 = num_array.pop(i)
  break
 else:
     print("Please type right number!")

for i in range(len(json_resp6["items"])):
    if choice6 in json_resp6["items"][i].values():
        ipspolicy_name = json_resp6["items"][i]["name"]
        ipspolicy_type = json_resp6["items"][i]["type"]
        ipspolicy_id = json_resp6["items"][i]["id"]

####<<using the IPS rule data and adding them to ipsfull>>####
##############################################################
ipsfull= {"ipsPolicy": {"name": "n", "id": "d", "type": "IntrusionPolicy"}, "logBegin": True, "logEnd": True, "sendEventsToFMC": True}
####<< enable Log >>####
########################
logingfull = {"logBegin": True, "logEnd": True, "sendEventsToFMC": True}
ipsfull['ipsPolicy']['name'] = ipspolicy_name
ipsfull['ipsPolicy']['id'] = ipspolicy_id
print('=================================================================================================')
print('=================================================================================================')
print('=================================================================================================')
choiceyesno=query_yes_no("did you choose the right Intrusion Policie?")

    ##### << getting Malware Policy infromation from FMC >> #####
################################################################################

###api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/filepolicies"
###url = url_start + ipaddr + api_path
###if (url[-1] == '/'):
###    url = url[:-1]
###num_array = list()

###try:
###    r16 = requests.get(url, headers=headers,params=querystring, verify=False)
###    status_code = r16.status_code
###    resp = r16.text
###    if (status_code == 200):
###        print ("The current Malware Policies are: ")
###        number=1
###        json_resp16 = json.loads(resp)
###        for i in range(len(json_resp16["items"])):
###            num_array.append(json_resp16["items"][i]["name"])
###            print ("%d. %s" % (number,json_resp16["items"][i]["name"]))
###            #inpolicy = json_resp6["items"][i]["name"]
###            number+=1

###    else:
###        r16.raise_for_status()
###        print("Error occurred in --> "+resp)
###except requests.exceptions.HTTPError as err:
###    print ("Error in connection --> "+str(err))
###finally:
###    if r16 : r16.close()
###while True:
### choicenum = int(input ("Type the number of the Malware Policy for which you would like to apply: "))
### choicenum-=1
### if choicenum in range(len(num_array)):
###  for i in range(len(num_array)):
###    if choicenum == i:
###      choice7 = num_array.pop(i)
###  break
### else:
###     print("Please type right number!")

###for i in range(len(json_resp16["items"])):
###    if choice7 in json_resp16["items"][i].values():
###        malwarepolicy_name = json_resp16["items"][i]["name"]
###        malwarepolicy_type = json_resp16["items"][i]["type"]
###        malwarepolicy_id = json_resp16["items"][i]["id"]

###malwarefull= {"filePolicy": {"name": "n", "id": "d", "type": "FilePolicy"}}
###malwarefull['filePolicy']['name'] = malwarepolicy_name
###malwarefull['filePolicy']['id'] = malwarepolicy_id
#print(ipspolicy_name)
#print(ipspolicy_type)
#print(ipspolicy_id)
#print(ipsfull)
#ips={"ipsPolicy": { "name": "Security Over Connectivity", "id": "abba9b63-bb10-4729-b901-2e2aa0f4491c","type": "IntrusionPolicy"},"logBegin": True,"logEnd": True,"sendEventsToFMC": True,}
#print(ipsfull)
#print(ips)
#= json.loads(resp)
#data.update(ips)
#data = remove_error_info(data)
#ips2 = json.dumps(data)
###print('=================================================================================================')
###print('=================================================================================================')
###print('=================================================================================================')
###choiceyesno=query_yes_no("did you choose the right Malware Policy?")



########################################################################################################
########################################################################################################
########################################################################################################
########################################################################################################

####<<Calling the Accesspolicies , adding number for each policy and display them to user to choose one>>####
#############################################################################################################

if choiceyesno == 1:
 api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies"    # param
 url = url_start + ipaddr + api_path
 if (url[-1] == '/'):
     url = url[:-1]

 num_array2= list()
 try:
     r2 = requests.get(url, headers=headers,params=querystring, verify=False)
     status_code = r2.status_code
     resp = r2.text
     if (status_code == 200):
         print ("The current Access Policies are: ")
         number=1
         json_resp1 = json.loads(resp)
         for i in range(len(json_resp1["items"])):
             num_array2.append(json_resp1["items"][i]["name"])
             print ("%d. %s" % (number,json_resp1["items"][i]["name"]))
             number+=1

     else:
         r2.raise_for_status()
         print("Error occurred in --> "+resp)
 except requests.exceptions.HTTPError as err:
     print ("Error in connection --> "+str(err))
 finally:
     if r2 : r2.close()

####<<choose number of the accesspolicies want to Modify>>####
##############################################################
 while True:
  choicenum2 = int(input ("Type the number of the Access Policy for which you would like to apply IPS and Logging features: "))
  choicenum2-=1
  if choicenum2 in range(len(num_array2)):
   for i in range(len(num_array2)):
    if choicenum2 == i:
      choice = num_array2.pop(i)
   break
  else:
     print("Please type right number!")




 for i in range(len(json_resp1["items"])):
     if choice in json_resp1["items"][i].values():
         container_id = json_resp1["items"][i]["id"]


 ##print(container_id)


####<< Accessing accesspolicy and modfiy each access-rule inside it and appling IPS and logging  >>####
#######################################################################################################
 api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/" + container_id + "/accessrules"    # param
 url = url_start + ipaddr + api_path
 if (url[-1] == '/'):
     url = url[:-1]

 print ("Applying IPS and Logging features to Access Rules........")
 try:
  global items
  global items2
  global items3
  items = None
  items2 = None
  items3 = None
  ##with open('rules6.text', 'w') as target3:

  for i in range(3):
     offsetStr = "?offset=%d&limit=1000" % (i*1000)
     url = url_start + ipaddr + api_path + offsetStr;
     r3 = requests.get(url, headers=headers, verify=False)
     status_code = r3.status_code
     resp = r3.text
     numcount=1
     ##with open('rules2.text', 'w') as target2:
      ##target2.write(resp)
     if (status_code == 200):
          if (i==0):
           items = json.loads(resp)
         ##  target2.write(resp)
          if (i==1):
           json_resp2= json.loads(resp)
           items2 = json.loads(resp)
        ##   target3.write("%s\n" % items2)
          if (i==2):
           items3 = json.loads(resp)

     else:
           r3.raise_for_status()
           print("Error occurred in --> "+resp)
  ##target3.close()
 except requests.exceptions.HTTPError as err:
     print ("Error in connection --> "+str(err))
 finally:
     if r3 : r3.close()



 policycount=0

 ####<<geting new Token from REST API and returns the headers>>########
###############################################################################
 r = None
 headers = {'Content-Type': 'application/json'}
 api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
 auth_url = url_start + ipaddr + api_auth_path
 try:
    r1 = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(user1,pass1), verify=False)
    auth_headers = r1.headers
    auth_token = auth_headers.get('X-auth-access-token', default=None)
    if auth_token == None:
        print("Authentication Token not found. Exiting...")
        sys.exit()
 except Exception as err:
    print ("Error in generating Authentication Token --> "+str(err))
    sys.exit()

 headers['X-auth-access-token']=auth_token
##############################################################################



 rules_count=0
####<< For Loop for first 1000 accesspolicies to Get and Put the IPS & Logging on them >>####
#############################################################################################

 for i in range(len(items["items"])):
     if (rules_count == 150 ):
      r = None
      headers = {'Content-Type': 'application/json'}
      api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
      auth_url = url_start + ipaddr + api_auth_path
      try:
          r1 = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(user1,pass1), verify=False)
          auth_headers = r1.headers
          auth_token = auth_headers.get('X-auth-access-token', default=None)
          if auth_token == None:
           print("Authentication Token not found. Exiting...")
           sys.exit()
      except Exception as err:
        print ("Error in generating Authentication Token --> "+str(err))
        sys.exit()
      headers['X-auth-access-token']=auth_token
     if (rules_count == 300):
      r = None
      headers = {'Content-Type': 'application/json'}
      api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
      auth_url = url_start + ipaddr + api_auth_path
      try:
          r1 = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(user1,pass1), verify=False)
          auth_headers = r1.headers
          auth_token = auth_headers.get('X-auth-access-token', default=None)
          if auth_token == None:
           print("Authentication Token not found. Exiting...")
           sys.exit()
      except Exception as err:
        print ("Error in generating Authentication Token --> "+str(err))
        sys.exit()
      headers['X-auth-access-token']=auth_token
     if (rules_count == 450):
      r = None
      headers = {'Content-Type': 'application/json'}
      api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
      auth_url = url_start + ipaddr + api_auth_path
      try:
          r1 = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(user1,pass1), verify=False)
          auth_headers = r1.headers
          auth_token = auth_headers.get('X-auth-access-token', default=None)
          if auth_token == None:
           print("Authentication Token not found. Exiting...")
           sys.exit()
      except Exception as err:
        print ("Error in generating Authentication Token --> "+str(err))
        sys.exit()
      headers['X-auth-access-token']=auth_token
     if (rules_count == 600):
      r = None
      headers = {'Content-Type': 'application/json'}
      api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
      auth_url = url_start + ipaddr + api_auth_path
      try:
          r1 = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(user1,pass1), verify=False)
          auth_headers = r1.headers
          auth_token = auth_headers.get('X-auth-access-token', default=None)
          if auth_token == None:
           print("Authentication Token not found. Exiting...")
           sys.exit()
      except Exception as err:
        print ("Error in generating Authentication Token --> "+str(err))
        sys.exit()
      headers['X-auth-access-token']=auth_token
     if (rules_count == 750):
      r = None
      headers = {'Content-Type': 'application/json'}
      api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
      auth_url = url_start + ipaddr + api_auth_path
      try:
          r1 = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(user1,pass1), verify=False)
          auth_headers = r1.headers
          auth_token = auth_headers.get('X-auth-access-token', default=None)
          if auth_token == None:
           print("Authentication Token not found. Exiting...")
           sys.exit()
      except Exception as err:
        print ("Error in generating Authentication Token --> "+str(err))
        sys.exit()
      headers['X-auth-access-token']=auth_token
     if (rules_count == 900):
      r = None
      headers = {'Content-Type': 'application/json'}
      api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
      auth_url = url_start + ipaddr + api_auth_path
      try:
          r1 = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(user1,pass1), verify=False)
          auth_headers = r1.headers
          auth_token = auth_headers.get('X-auth-access-token', default=None)
          if auth_token == None:
           print("Authentication Token not found. Exiting...")
           sys.exit()
      except Exception as err:
        print ("Error in generating Authentication Token --> "+str(err))
        sys.exit()
      headers['X-auth-access-token']=auth_token
     rules_count+=1
     print("Appling IPS and Logging on Rule number: %d " % rules_count)
     rule_id = items["items"][i]["id"]
     api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/" + container_id + "/accessrules/" + rule_id
     url = url_start + ipaddr + api_path
     if (url[-1] == '/'):
      url = url[:-1]
     r1 = requests.get(url, headers=headers, verify=False)
     status_code = r1.status_code
     resp = r1.text
     if (status_code == 200):
         json_resp = json.loads(resp)
         ips=ipsfull.copy()
         log=logingfull.copy()
         ###malware=malwarefull.copy()
         data_log = json.loads(resp)
         data = json.loads(resp)
         data.update(ips)
         ###data.update(malware)
         data = remove_error_info(data)
         json_string = json.dumps(data)
         data_log = remove_error_info(data_log)
         json_string = json.dumps(data_log)
         if data["action"] == 'ALLOW':
          r1 = requests.put(url, data=json.dumps(data ,indent=25), headers=headers, verify=False)
          status_code = r1.status_code
          resp = r1.text
          if (status_code == 200):
             json_resp = json.loads(resp)
             print ("IPS and Logging features applied to Acces Rule name << %s >>---> Done"%(data["name"]))
             policycount+=1
          else:
            r1.raise_for_status()
            print("Status code:-->"+status_code)
            print("Error occurred in --> "+resp)
         else:
          data_log.update(log)
          r1 = requests.put(url, data=json.dumps(data_log ,indent=25), headers=headers, verify=False)
          status_code = r1.status_code
          resp = r1.text
          if (status_code == 200):
             json_resp = json.loads(resp)
             print("Applying  Logging to Access rule << %s >> , rule action is blocked."%(data_log["name"]))
     else:
      r1.raise_for_status()
      print("Error occurred in --> "+resp)
 number+=1
 time.sleep(.5)

 if (items2['paging']['count'] == 0):
  print("              =====                  ")
  print("               ===                   ")
  print("                =                    ")
  print("Thank you for using this Script, Bye!")

  key = input('Press Any Key To Exit.')
  quit()



 ####<<geting new Token from REST API and returns the headers>>########
###############################################################################
 r = None
 headers = {'Content-Type': 'application/json'}
 api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
 auth_url = url_start + ipaddr + api_auth_path
 try:
    r1 = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(user1,pass1), verify=False)
    auth_headers = r1.headers
    auth_token = auth_headers.get('X-auth-access-token', default=None)
    if auth_token == None:
        print("Authentication Token not found. Exiting...")
        sys.exit()
 except Exception as err:
    print ("Error in generating Authentication Token --> "+str(err))
    sys.exit()

 headers['X-auth-access-token']=auth_token
##############################################################################

####<< For Loop for second 1000 accesspolicies to Get and Put the IPS & Logging on them >>####
#############################################################################################


 for i in range(len(items2["items"])):
     if (rules_count == 1050 ):
      r = None
      headers = {'Content-Type': 'application/json'}
      api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
      auth_url = url_start + ipaddr + api_auth_path
      try:
          r1 = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(user1,pass1), verify=False)
          auth_headers = r1.headers
          auth_token = auth_headers.get('X-auth-access-token', default=None)
          if auth_token == None:
           print("Authentication Token not found. Exiting...")
           sys.exit()
      except Exception as err:
        print ("Error in generating Authentication Token --> "+str(err))
        sys.exit()
      headers['X-auth-access-token']=auth_token
     if (rules_count == 1200):
      r = None
      headers = {'Content-Type': 'application/json'}
      api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
      auth_url = url_start + ipaddr + api_auth_path
      try:
          r1 = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(user1,pass1), verify=False)
          auth_headers = r1.headers
          auth_token = auth_headers.get('X-auth-access-token', default=None)
          if auth_token == None:
           print("Authentication Token not found. Exiting...")
           sys.exit()
      except Exception as err:
        print ("Error in generating Authentication Token --> "+str(err))
        sys.exit()
      headers['X-auth-access-token']=auth_token
     if (rules_count == 1350):
      r = None
      headers = {'Content-Type': 'application/json'}
      api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
      auth_url = url_start + ipaddr + api_auth_path
      try:
          r1 = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(user1,pass1), verify=False)
          auth_headers = r1.headers
          auth_token = auth_headers.get('X-auth-access-token', default=None)
          if auth_token == None:
           print("Authentication Token not found. Exiting...")
           sys.exit()
      except Exception as err:
        print ("Error in generating Authentication Token --> "+str(err))
        sys.exit()
      headers['X-auth-access-token']=auth_token
     if (rules_count == 1500):
      r = None
      headers = {'Content-Type': 'application/json'}
      api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
      auth_url = url_start + ipaddr + api_auth_path
      try:
          r1 = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(user1,pass1), verify=False)
          auth_headers = r1.headers
          auth_token = auth_headers.get('X-auth-access-token', default=None)
          if auth_token == None:
           print("Authentication Token not found. Exiting...")
           sys.exit()
      except Exception as err:
        print ("Error in generating Authentication Token --> "+str(err))
        sys.exit()
      headers['X-auth-access-token']=auth_token
     if (rules_count == 1650):
      r = None
      headers = {'Content-Type': 'application/json'}
      api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
      auth_url = url_start + ipaddr + api_auth_path
      try:
          r1 = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(user1,pass1), verify=False)
          auth_headers = r1.headers
          auth_token = auth_headers.get('X-auth-access-token', default=None)
          if auth_token == None:
           print("Authentication Token not found. Exiting...")
           sys.exit()
      except Exception as err:
        print ("Error in generating Authentication Token --> "+str(err))
        sys.exit()
      headers['X-auth-access-token']=auth_token
     if (rules_count == 1800):
      r = None
      headers = {'Content-Type': 'application/json'}
      api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
      auth_url = url_start + ipaddr + api_auth_path
      try:
          r1 = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(user1,pass1), verify=False)
          auth_headers = r1.headers
          auth_token = auth_headers.get('X-auth-access-token', default=None)
          if auth_token == None:
           print("Authentication Token not found. Exiting...")
           sys.exit()
      except Exception as err:
        print ("Error in generating Authentication Token --> "+str(err))
        sys.exit()
      headers['X-auth-access-token']=auth_token
     if (rules_count == 1950):
      r = None
      headers = {'Content-Type': 'application/json'}
      api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
      auth_url = url_start + ipaddr + api_auth_path
      try:
          r1 = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(user1,pass1), verify=False)
          auth_headers = r1.headers
          auth_token = auth_headers.get('X-auth-access-token', default=None)
          if auth_token == None:
           print("Authentication Token not found. Exiting...")
           sys.exit()
      except Exception as err:
        print ("Error in generating Authentication Token --> "+str(err))
        sys.exit()
      headers['X-auth-access-token']=auth_token
     rules_count+=1
     print("Rules Count: %d " % rules_count)
     rule_id = items["items"][i]["id"]
     api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/" + container_id + "/accessrules/" + rule_id
     url = url_start + ipaddr + api_path
     if (url[-1] == '/'):
      url = url[:-1]
     r1 = requests.get(url, headers=headers, verify=False)
     status_code = r1.status_code
     resp = r1.text
     if (status_code == 200):
         json_resp = json.loads(resp)
         ips=ipsfull.copy()
         log=logingfull.copy()
         ###malware=malwarefull.copy()
         data_log = json.loads(resp)
         data = json.loads(resp)
         data.update(ips)
         ###data.update(malware)
         data = remove_error_info(data)
         json_string = json.dumps(data)
         data_log = remove_error_info(data_log)
         json_string = json.dumps(data_log)
         if data["action"] == 'ALLOW':
          r1 = requests.put(url, data=json.dumps(data ,indent=25), headers=headers, verify=False)
          status_code = r1.status_code
          resp = r1.text
          if (status_code == 200):
             json_resp = json.loads(resp)
             print ("IPS and Logging features applied to Acces Rule name << %s >>---> Done"%(data["name"]))
             policycount+=1
          else:
            r1.raise_for_status()
            print("Status code:-->"+status_code)
            print("Error occurred in --> "+resp)
         else:
          data_log.update(log)
          r1 = requests.put(url, data=json.dumps(data_log ,indent=25), headers=headers, verify=False)
          status_code = r1.status_code
          resp = r1.text
          if (status_code == 200):
             json_resp = json.loads(resp)
             print("Applying  Logging to Access rule << %s >> , rule action is blocked."%(data_log["name"]))
     else:
       r.raise_for_status()
       print("Error occurred in --> "+resp)
 number+=1
 time.sleep(.5)

 if (items3['paging']['count'] == 0):
  print("              =====                  ")
  print("               ===                   ")
  print("                =                    ")
  print("Thank you for using this Script, Bye!")

  key = input('Press Any Key To Exit.')
  quit()

 ####<<geting new Token from REST API and returns the headers>>########
###############################################################################
 r = None
 headers = {'Content-Type': 'application/json'}
 api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
 auth_url = url_start + ipaddr + api_auth_path
 try:
    r1 = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(user1,pass1), verify=False)
    auth_headers = r1.headers
    auth_token = auth_headers.get('X-auth-access-token', default=None)
    if auth_token == None:
        print("Authentication Token not found. Exiting...")
        sys.exit()
 except Exception as err:
    print ("Error in generating Authentication Token --> "+str(err))
    sys.exit()

 headers['X-auth-access-token']=auth_token
##############################################################################


####<< For Loop for third 1000 accesspolicies to Get and Put the IPS & Logging on them >>####
#############################################################################################

 for i in range(len(items3["items"])):
     if (rules_count == 2100 ):
      r = None
      headers = {'Content-Type': 'application/json'}
      api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
      auth_url = url_start + ipaddr + api_auth_path
      try:
          r1 = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(user1,pass1), verify=False)
          auth_headers = r1.headers
          auth_token = auth_headers.get('X-auth-access-token', default=None)
          if auth_token == None:
           print("Authentication Token not found. Exiting...")
           sys.exit()
      except Exception as err:
        print ("Error in generating Authentication Token --> "+str(err))
        sys.exit()
      headers['X-auth-access-token']=auth_token
     if (rules_count == 2250):
      r = None
      headers = {'Content-Type': 'application/json'}
      api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
      auth_url = url_start + ipaddr + api_auth_path
      try:
          r1 = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(user1,pass1), verify=False)
          auth_headers = r1.headers
          auth_token = auth_headers.get('X-auth-access-token', default=None)
          if auth_token == None:
           print("Authentication Token not found. Exiting...")
           sys.exit()
      except Exception as err:
        print ("Error in generating Authentication Token --> "+str(err))
        sys.exit()
      headers['X-auth-access-token']=auth_token
     if (rules_count == 2400):
      r = None
      headers = {'Content-Type': 'application/json'}
      api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
      auth_url = url_start + ipaddr + api_auth_path
      try:
          r1 = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(user1,pass1), verify=False)
          auth_headers = r1.headers
          auth_token = auth_headers.get('X-auth-access-token', default=None)
          if auth_token == None:
           print("Authentication Token not found. Exiting...")
           sys.exit()
      except Exception as err:
        print ("Error in generating Authentication Token --> "+str(err))
        sys.exit()
      headers['X-auth-access-token']=auth_token
     if (rules_count == 2550):
      r = None
      headers = {'Content-Type': 'application/json'}
      api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
      auth_url = url_start + ipaddr + api_auth_path
      try:
          r1 = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(user1,pass1), verify=False)
          auth_headers = r1.headers
          auth_token = auth_headers.get('X-auth-access-token', default=None)
          if auth_token == None:
           print("Authentication Token not found. Exiting...")
           sys.exit()
      except Exception as err:
        print ("Error in generating Authentication Token --> "+str(err))
        sys.exit()
      headers['X-auth-access-token']=auth_token
     if (rules_count == 2700):
      r = None
      headers = {'Content-Type': 'application/json'}
      api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
      auth_url = url_start + ipaddr + api_auth_path
      try:
          r1 = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(user1,pass1), verify=False)
          auth_headers = r1.headers
          auth_token = auth_headers.get('X-auth-access-token', default=None)
          if auth_token == None:
           print("Authentication Token not found. Exiting...")
           sys.exit()
      except Exception as err:
        print ("Error in generating Authentication Token --> "+str(err))
        sys.exit()
      headers['X-auth-access-token']=auth_token
     if (rules_count == 2850):
      r = None
      headers = {'Content-Type': 'application/json'}
      api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
      auth_url = url_start + ipaddr + api_auth_path
      try:
          r1 = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(user1,pass1), verify=False)
          auth_headers = r1.headers
          auth_token = auth_headers.get('X-auth-access-token', default=None)
          if auth_token == None:
           print("Authentication Token not found. Exiting...")
           sys.exit()
      except Exception as err:
        print ("Error in generating Authentication Token --> "+str(err))
        sys.exit()
      headers['X-auth-access-token']=auth_token
     rules_count+=1
     print("Rules Count: %d " % rules_count)
     rule_id = items["items"][i]["id"]
     api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/" + container_id + "/accessrules/" + rule_id
     url = url_start + ipaddr + api_path
     if (url[-1] == '/'):
      url = url[:-1]
     ### print("URL: %s " % url)
     r1 = requests.get(url, headers=headers, verify=False)
     status_code = r1.status_code
     resp = r1.text
     if (status_code == 200):
         json_resp = json.loads(resp)
         ips=ipsfull.copy()
         log=logingfull.copy()
         ###malware=malwarefull.copy()
         data_log = json.loads(resp)
         data = json.loads(resp)
         data.update(ips)
         ###data.update(malware)
         data = remove_error_info(data)
         json_string = json.dumps(data)
         data_log = remove_error_info(data_log)
         json_string = json.dumps(data_log)
         if data["action"] == 'ALLOW':
          r1 = requests.put(url, data=json.dumps(data ,indent=25), headers=headers, verify=False)
          status_code = r1.status_code
          resp = r1.text
          if (status_code == 200):
             json_resp = json.loads(resp)
             print ("IPS and Logging features applied to Acces Rule name << %s >>---> Done"%(data["name"]))
             policycount+=1
          else:
            r1.raise_for_status()
            print("Status code:-->"+status_code)
            print("Error occurred in --> "+resp)
         else:
          data_log.update(log)
          r1 = requests.put(url, data=json.dumps(data_log ,indent=25), headers=headers, verify=False)
          status_code = r1.status_code
          resp = r1.text
          if (status_code == 200):
             json_resp = json.loads(resp)
             print("Applying  Logging to Access rule << %s >> , rule action is blocked."%(data_log["name"]))
     else:
       r.raise_for_status()
       print("Error occurred in --> "+resp)
 number+=1
 time.sleep(.5)



 print('                                                                                                 ')
 print('                                                                                                 ')
 print('                                                                                                 ')
 print('=================================================================================================')
 print('=================================================================================================')
 print('=================================================================================================')
 print("IPS and Logging features have been applied into %d Access Rule" %(policycount))
else:
    print("              =====                  ")
    print("               ===                   ")
    print("                =                    ")
    print("Thank you for using this Script, Bye!")
    key = input('Press Any Key To Exit.')
    quit()


print("              =====                  ")
print("               ===                   ")
print("                =                    ")
print("Thank you for using this Script, Bye!")

key = input('Press Any Key To Exit.')
quit()
