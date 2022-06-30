# -*- coding: utf-8 -*-
"""
Created on Tue Jun 28 10:23:01 2022

@author: x64
"""
import requests, json
from credentials import api_key

ip_addr = '192.168.1.100'
port = 443

def api_call(ip_addr, port, command, json_payload, sid):
    url = 'https://' + ip_addr + ':' + str(port) + '/web_api/' + command
    if sid == '':
        request_headers = {'Content-Type' : 'application/json'}
    else:
        request_headers = {'Content-Type' : 'application/json', 'X-chkp-sid' : sid}
    r = requests.post(url,data=json.dumps(json_payload), headers=request_headers,verify=False)
    return r.json()                                        

def login(api_key):
    payload = {'api-key' : api_key}
    response = api_call('192.168.1.100', 443, 'login', payload, '')
    # return response
    return response["sid"]

def logout(sid):
    response = api_call('192.168.1.100', 443,'logout', {} ,sid)
    return response["message"]

sid = login(api_key)
# sid = "eSrXCpFty4-6-kcsKLuPmmmbInZCyN8Wi3DpNHTDDzs"
print('session id: ' + sid)



# add_access_data = {"layer" : "Network","position" : 1,"name" : "Rule 1","service" : [ "SMTP", "AOL" ]}
# add_access_result = api_call(ip_addr, port, 'add-access-rule', add_access_data, sid)
# print(json.dumps(add_access_result))

set_access_data = {'rule-number':'1','layer':'Network','action':'Accept'}
set_access_result = api_call(ip_addr, port, 'set-access-rule', set_access_data, sid)
print(json.dumps(set_access_result))

del_rule_data = {"rule-number" : "1", "layer" : "Network"}
del_rule_result = api_call(ip_addr, port, "delete-access-rule", del_rule_data, sid)
print(json.dumps(del_rule_result))

publish_result = api_call(ip_addr, port, 'publish', {}, sid)
print('publish result: ' + json.dumps(publish_result))

# sessions_data = {"limit" : 50,"offset" : 0,"details-level" : "standard"}
# sessions = api_call(ip_addr, port, 'show-sessions', sessions_data, sid)
# print(json.dumps(sessions))
# discard_changes = api_call(ip_addr, port, 'discard', {}, sid)

new_policy = {"policy-package" : "standard","access" : True,"threat-prevention" : True,"targets" : ["SG"]}
new_policy_result = api_call(ip_addr, port, 'install-policy', new_policy, sid)
logout(sid)