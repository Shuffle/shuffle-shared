import os
import ast
import sys
import re
import copy
import time 
import base64
import json
import random
import liquid
import logging
import urllib3
import hashlib
import zipfile
import asyncio
import requests
import http.client
import urllib.parse
import jinja2 
import datetime
import dateutil

import threading
import concurrent.futures

from io import StringIO as StringBuffer, BytesIO 
from liquid import Liquid, defaults
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress the warning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


runtime = os.getenv("SHUFFLE_SWARM_CONFIG", "")

###
###
###
#### Filters for liquidpy
###
###
###

defaults.MODE = 'wild'
defaults.FROM_FILE = False
from liquid.filters.manager import FilterManager
from liquid.filters.standard import standard_filter_manager

shuffle_filters = FilterManager()
for key, value in standard_filter_manager.filters.items():
    shuffle_filters.filters[key] = value

#@shuffle_filters.register
#def plus(a, b):
#    try:
#        a = int(a)
#    except:
#        a = 0
#
#    try:
#        b = int(b)
#    except:
#        b = 0
#
#    return standard_filter_manager.filters["plus"](a, b)
#
#@shuffle_filters.register
#def minus(a, b):
#    a = int(a)
#    b = int(b)
#    return standard_filter_manager.filters["minus"](a, b)
#
#@shuffle_filters.register
#def multiply(a, b):
#    a = int(a)
#    b = int(b)
#    return standard_filter_manager.filters["multiply"](a, b)
#
#@shuffle_filters.register
#def divide(a, b):
#    a = int(a)
#    b = int(b)
#    return standard_filter_manager.filters["divide"](a, b)

@shuffle_filters.register
def md5(a):
    a = str(a)
    return hashlib.md5(a.encode('utf-8')).hexdigest()
    
@shuffle_filters.register
def sha256(a):
    a = str(a)
    return hashlib.sha256(str(a).encode("utf-8")).hexdigest() 

@shuffle_filters.register
def md5_base64(a):
    a = str(a)
    foundhash = hashlib.md5(a.encode('utf-8')).hexdigest()
    return base64.b64encode(foundhash.encode('utf-8'))
    
@shuffle_filters.register
def base64_encode(a):
    a = str(a)

    try:
        return base64.b64encode(a.encode('utf-8')).decode()
    except:
        return base64.b64encode(a).decode()

@shuffle_filters.register
def base64_decode(a):
    a = str(a)

    if "-" in a: 
        a = a.replace("-", "+", -1)

    if "_" in a:
        a = a.replace("_", "/", -1)

    # Fix padding
    if len(a) % 4 != 0:
        a += "=" * (4 - len(a) % 4)

    try:
        return base64.b64decode(a).decode("unicode_escape")
    except:
        try:
            return base64.b64decode(a).decode()
        except:
            return base64.b64decode(a)

@shuffle_filters.register
def json_parse(a):
    return json.loads(str(a))

@shuffle_filters.register
def as_object(a):
    return json.loads(str(a))

@shuffle_filters.register
def ast_eval(a):
    return ast.literal_eval(str(a))

@shuffle_filters.register
def escape_string(a):
    a = str(a)
    return a.replace("\\\'", "\'", -1).replace("\\\"", "\"", -1).replace("'", "\\\'", -1).replace("\"", "\\\"", -1)

@shuffle_filters.register
def json_escape(a):
    a = str(a)
    return a.replace("\\\'", "\'", -1).replace("\\\"", "\"", -1).replace("'", "\\\\\'", -1).replace("\"", "\\\\\"", -1)

@shuffle_filters.register
def escape_json(a):
    a = str(a)
    return a.replace("\\\'", "\'", -1).replace("\\\"", "\"", -1).replace("'", "\\\\\'", -1).replace("\"", "\\\\\"", -1)

# By default using json escape to add all backslashes
@shuffle_filters.register
def escape(a):
    a = str(a)
    return json_escape(a)


@shuffle_filters.register
def neat_json(a):
    try:
        a = json.loads(a)
    except:
        pass 

    return json.dumps(a, indent=4, sort_keys=True)

@shuffle_filters.register
def flatten(a):
    a = list(a)

    flat_list = [a for xs in a for a in xs]
    return flat_list

@shuffle_filters.register
def last(a):
    try:
        a = json.loads(a)
    except:
        pass

    if len(a) == 0:
        return ""

    return a[-1]

@shuffle_filters.register
def first(a):
    try:
        a = json.loads(a)
    except:
        pass

    if len(a) == 0:
        return ""

    return a[0]
    

@shuffle_filters.register
def csv_parse(a):
    a = str(a)
    splitdata = a.split("\n")
    columns = []
    if len(splitdata) > 1:
        columns = splitdata[0].split(",")
    else:
        return a.split("\n")

    allitems = []
    cnt = -1
    for item in splitdata[1:]:
        cnt += 1
        commasplit = item.split(",")

        fullitem = {}
        fullitem["unparsed"] = item
        fullitem["index"] = cnt 
        fullitem["parsed"] = {}
        if len(columns) != len(commasplit):

            if len(commasplit) > len(columns):
                diff = len(commasplit)-len(columns)

                try:
                    commasplit = commasplit[0:len(commasplit)-diff]
                except:
                    pass
            else:
                for item in range(0, len(columns)-len(commasplit)):
                    commasplit.append("")

        for key in range(len(columns)):
            try:
                fullitem["parsed"][columns[key]] = commasplit[key]
            except:
                continue 
        
        allitems.append(fullitem)

    try:
        return json.dumps(allitems)
    except:
        return allitems

@shuffle_filters.register
def parse_csv(a):
    return csv_parse(a)

@shuffle_filters.register
def format_csv(a):
    return csv_parse(a)

@shuffle_filters.register
def csv_format(a):
    return csv_parse(a)@standard_filter_manager.register

@shuffle_filters.register
def split(base, sep):
    if not sep:
        try:
            return json.dumps(list(base))
        except:
            return list(base)

    try:
        return json.dumps(base.split(sep))
    except:
        return base.split(sep)


###
###
###
###
###
###
###


class AppBase:
    __version__ = None
    app_name = None

    def __init__(self, redis=None, logger=None, console_logger=None):#, docker_client=None):
        self.logger = logger if logger is not None else logging.getLogger("AppBaseLogger")

        if not os.getenv("SHUFFLE_LOGS_DISABLED") == "true":
            self.log_capture_string = StringBuffer()
            ch = logging.StreamHandler(self.log_capture_string)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            ch.setFormatter(formatter)
            logger.addHandler(ch)

        self.redis=redis
        self.console_logger = logger if logger is not None else logging.getLogger("AppBaseLogger")

        # apikey is for the user / org
        # authorization is for the specific workflow

        self.url = os.getenv("CALLBACK_URL",  "https://shuffler.io")
        self.base_url = os.getenv("BASE_URL", "https://shuffler.io")
        self.action = os.getenv("ACTION", "")
        self.original_action = os.getenv("ACTION", "")
        self.authorization = os.getenv("AUTHORIZATION", "")
        self.current_execution_id = os.getenv("EXECUTIONID", "")
        self.full_execution = os.getenv("FULL_EXECUTION", "") 
        self.result_wrapper_count = 0

        # Make start time with milliseconds
        self.start_time = int(time.time_ns())

        self.action_result = {
            "action": self.action,
            "authorization": self.authorization,
            "execution_id": self.current_execution_id,
            "result": f"",
            "started_at": self.start_time,
            "status": "",
            "completed_at": int(time.time_ns()),
        }

        self.proxy_config = {
            "http": os.getenv("HTTP_PROXY", ""),
            "https": os.getenv("HTTPS_PROXY", ""),
            "no_proxy": os.getenv("NO_PROXY", ""),
        }

        if len(os.getenv("SHUFFLE_INTERNAL_HTTP_PROXY", "")) > 0:
            self.proxy_config["http"] = os.getenv("SHUFFLE_INTERNAL_HTTP_PROXY", "")

        if len(os.getenv("SHUFFLE_INTERNAL_HTTPS_PROXY", "")) > 0:
            self.proxy_config["https"] = os.getenv("SHUFFLE_INTERNAL_HTTP_PROXY", "")

        if len(os.getenv("SHUFFLE_INTERNAL_NO_PROXY", "")) > 0:
            self.proxy_config["no_proxy"] = os.getenv("SHUFFLE_INTERNAL_NO_PROXY", "")

        try:
            if self.proxy_config["http"].lower() == "noproxy":
                self.proxy_config["http"] = ""
            if self.proxy_config["https"].lower() == "noproxy":
                self.proxy_config["https"] = ""
        except Exception as e:
            self.logger.info(f"[WARNING] Failed setting proxy config: {e}. NOT important if running apps with webserver. This is NOT critical.")


        if isinstance(self.action, str):
            try:
                self.action = json.loads(self.action)
                self.original_action = json.loads(self.action)
            except Exception as e:
                pass

        if len(self.base_url) == 0:
            self.base_url = self.url


        self.local_storage = []

    # Checks output for whether it should be automatically parsed or not
    def run_magic_parser(self, input_data):
        if not isinstance(input_data, str):
            return input_data

        # Don't touch existing JSON/lists
        if (input_data.startswith("[") and input_data.endswith("]")) or (input_data.startswith("{") and input_data.endswith("}")):
            return input_data

        if len(input_data) < 3:
            return input_data

        # Don't touch large data.
        if len(input_data) > 100000:
            return input_data

        if not "\n" in input_data and not "," in input_data: 
            return input_data

        new_input = input_data
        try:
            #new_input.strip()
            new_input = input_data.split()
            new_return = []

            index = 0
            for item in new_input:
                splititem = ","
                if ", " in item:
                    splititem = ", "
                elif "," in item:
                    splititem = ","
                else:
                    new_return.append(item)

                    index += 1
                    continue

                for subitem in item.split(splititem):
                    new_return.insert(index, subitem) 

                    index += 1

                    # Prevent large data or infinite loops
                    if index > 10000:
                        #self.logger.info(f"[DEBUG] Infinite loop. Returning default data.")
                        return input_data

            fixed_return = []
            for item in new_return:
                if not item:
                    continue

                if not isinstance(item, str):
                    fixed_return.append(item)
                    continue

                if item.endswith(","):
                    item = item[0:-1]
                
                fixed_return.append(item)

            new_input = fixed_return
        except Exception as e:
            # Not used anymore
            #self.logger.info(f"[ERROR] Failed to run magic parser (2): {e}")
            return input_data

        try:
            new_input = input_data.split()
        except Exception as e:
            self.logger.info(f"[ERROR] Failed to run parser during split (1): {e}")
            return input_data

        # Won't ever touch this one?
        if isinstance(new_input, list) or isinstance(new_input, object):
            try:
                return json.dumps(new_input)
            except Exception as e:
                self.logger.info(f"[ERROR] Failed to run magic parser (3): {e}")
            
        return new_input

    def prepare_response(self, request):
        try:
            parsedheaders = {}
            for key, value in request.headers.items():
                parsedheaders[key] = value

            cookies = {}
            if request.cookies:
                for key, value in request.cookies.items():
                    cookies[key] = value

            
            jsondata = request.text
            try:
                jsondata = json.loads(jsondata)
            except:
                pass

            return json.dumps({
                "success": True,
                "status": request.status_code,
                "url": request.url,
                "body": jsondata,
                "headers": parsedheaders,
                "cookies":cookies,
            })
        except Exception as e:
            return request.text

    # Fixes pattern issues in json/liquid based on input and supplied patterns
    def patternfix_string(self, liquiddata, patterns, regex_patterns, inputtype="liquid"):
        if not inputtype or inputtype == "liquid":
            if "{{" not in liquiddata or "}}" not in liquiddata:
                return liquiddata 
        elif inputtype == "json":
            liquiddata = liquiddata.strip()
    
            # Validating if it looks like json or not
            if liquiddata[0] == "{" and liquiddata[len(liquiddata)-1] == "}":
                pass
            else:
                if liquiddata[0] == "[" and liquiddata[len(liquiddata)-1] == "]":
                    pass
                else:
                    return liquiddata
    
            # If it's already json, don't touch it
            try:
                json.loads(liquiddata)
                return liquiddata
            except Exception as e:
                pass
        else:
            print("No replace handler for %s" % inputtype)
            return liquiddata
    
        skipkeys = [" "]
        newoutput = liquiddata[:]
        for pattern in patterns:
            keylocations = []
            parsedvalue = ""
            record = False
            index = -1
            for key in liquiddata:
        
                # Return instant if possible
                if inputtype == "json":
                    try:
                        json.loads(newoutput)
                        return newoutput
                    except:
                        pass
    
                index += 1
                if not key:
                    if record:
                        keylocations.append(index)
                        parsedvalue += key
    
                    continue
    
                if key in skipkeys:
                    if record:
                        keylocations.append(index)
                        parsedvalue += key
    
                    continue
    
                if key == pattern[0] and not record:
                    record = True
    
                if key not in pattern:
                    keylocations = []
                    parsedvalue = ""
                    record = False
    
                if record:
                    keylocations.append(index)
                    parsedvalue += key
    
                if len(parsedvalue) == 0:
                    continue
    
                evaluated_value = parsedvalue[:]
                for skipkey in skipkeys:
                    evaluated_value = "".join(evaluated_value.split(skipkey))
    
                if evaluated_value == pattern:
                    #print("Found matching: %s (%s)" % (parsedvalue, keylocations))
                    #print("Should replace with: %s" % patterns[pattern])
    
                    newoutput = newoutput.replace(parsedvalue, patterns[pattern], -1)
    
            # Return instant if possible
            if inputtype == "json":
                try:
                    json.loads(newoutput)
                    return newoutput
                except:
                    pass
    
    
        for pattern in regex_patterns:
            newlines = []
            for line in newoutput.split("\n"):
                replaced_line = re.sub(pattern, regex_patterns[pattern], line)
                newlines.append(replaced_line)
    
            newoutput = "\n".join(newlines)
    
            # Return instant if possible
            if inputtype == "json":
                try:
                    json.loads(newoutput)
                    return newoutput
                except:
                    pass

        # Dont return json properly unless actually json
        if inputtype == "json":
            try:
                json.loads(newoutput)
                return newoutput
            except:
                # Returns original if json fixing didn't work
                return liquiddata
    
        return newoutput

    # FIXME: Add more info like logs in here.
    # Docker logs: https://forums.docker.com/t/docker-logs-inside-the-docker-container/68190/2
    def send_result(self, action_result, headers, stream_path):
        if action_result["status"] == "EXECUTING":
            action_result["status"] = "FAILURE"

        try:
            if self.action["run_magic_output"] == True:
                action_result["result"] = self.run_magic_parser(action_result["result"])
        except KeyError as e:
            pass 
        except Exception as e:
            pass

        # Try it with some magic

        action_result["completed_at"] = int(time.time_ns())
        #if isinstance(action_result, 

        # FIXME: Add cleanup of parameters to not send to frontend here
        params = {}

        self.base_url = "https://frankfurt.shuffler.io"
        # I wonder if this actually works 
        url = "%s%s" % (self.base_url, stream_path)
        self.logger.info("[INFO] WORKINGGGG %d" % len(ret))



        try:
            log_contents = "disabled: add env SHUFFLE_LOGS_DISABLED=true to Orborus to re-enable logs for apps. Can not be enabled natively in Cloud except in Hybrid mode."
            if not os.getenv("SHUFFLE_LOGS_DISABLED") == "true":
                log_contents = self.log_capture_string.getvalue()

            if len(action_result["action"]["parameters"]) == 0:
                action_result["action"]["parameters"] = []

            param_found = False
            for param in action_result["action"]["parameters"]:
                if param["name"] == "shuffle_action_logs": 
                    param_found = True
                    break

            if not param_found:
                action_result["action"]["parameters"].append({
                    "name": "shuffle_action_logs",
                    "value": log_contents,
                })

        except Exception as e:
            pass

        try:
            finished = False
            ret = {}
            for i in range (0, 10):
                # Random sleeptime between 0 and 1 second, with 0.1 increments
                sleeptime = float(random.randint(0, 10) / 10)

                try:
                    ret = requests.post(url, headers=headers, json=action_result, timeout=10, verify=False, proxies=self.proxy_config)

                    #self.logger.info(f"""[DEBUG] Successful result request: Status= {ret.status_code} (break on 200/201) & Action status: {action_result["status"]}. Response= {ret.text}""")
                    if ret.status_code == 200 or ret.status_code == 201:
                        finished = True
                        break
                    else:
                        # FIXME: Add a checker for 403, and Proxy logs failing
                        self.logger.info(f"[ERROR] Bad resp ({ret.status_code}) in send_result for url '{url}'")
                        time.sleep(sleeptime)
            

                # Proxyerrror
                except requests.exceptions.ProxyError as e:
                    self.proxy_config = {}
                    continue

                except requests.exceptions.RequestException as e:
                    time.sleep(sleeptime)

                    # Check if we have a read timeout. If we do, exit as we most likely sent the result without getting a good result
                    if "Read timed out" in str(e):
                        self.logger.warning(f"[WARNING] Read timed out: {e}")
                        finished = True
                        break

                    if "Max retries exceeded with url" in str(e):
                        self.logger.warning(f"[WARNING] Max retries exceeded with url: {e}")
                        finished = True
                        break

                    #time.sleep(5)
                    continue
                except TimeoutError as e:
                    time.sleep(sleeptime)

                    #time.sleep(5)
                    continue
                except requests.exceptions.ConnectionError as e:
                    time.sleep(sleeptime)

                    #time.sleep(5)
                    continue
                except http.client.RemoteDisconnected as e:
                    time.sleep(sleeptime)

                    #time.sleep(5)
                    continue
                except urllib3.exceptions.ProtocolError as e:
                    time.sleep(0.1)

                    #time.sleep(5)
                    continue

                #time.sleep(5)

            if not finished:
                # Not sure why this would work tho :)
                action_result["status"] = "FAILURE"
                action_result["result"] = json.dumps({"success": False, "reason": "POST error: Failed connecting to %s over 10 retries to the backend" % url})
                self.send_result(action_result, {"Content-Type": "application/json", "Authorization": "Bearer %s" % self.authorization}, "/api/v1/streams")
                return
        
        except requests.exceptions.ConnectionError as e:
            #self.logger.info(f"[DEBUG] Unexpected ConnectionError happened: {e}")
            pass
        except TypeError as e:
            action_result["status"] = "FAILURE"
            action_result["result"] = json.dumps({"success": False, "reason": "Typeerror when sending to backend URL %s" % url})

            ret = requests.post("%s%s" % (self.base_url, stream_path), headers=headers, json=action_result, verify=False, proxies=self.proxy_config)
            #self.logger.info(f"[DEBUG] Result: {ret.status_code}")
            #if ret.status_code != 200:
            #    pr
                
            #self.logger.info(f"[DEBUG] TypeError request: Status= {ret.status_code} & Response= {ret.text}")
        except http.client.RemoteDisconnected as e:
            self.logger.info(f"[DEBUG] Expected Remotedisconnect happened: {e}")
        except urllib3.exceptions.ProtocolError as e:
            self.logger.info(f"[DEBUG] Expected ProtocolError happened: {e}")

        
        # FIXME: Re-enable data flushing otherwise we'll overload it all
        # Or nah?
        if not os.getenv("SHUFFLE_LOGS_DISABLED") == "true":
            try:
                self.log_capture_string.flush()
                #self.log_capture_string.close()
                #pass
            except Exception as e:
                pass

    #async def cartesian_product(self, L):
    def cartesian_product(self, L):
        if L:
            #return {(a, ) + b for a in L[0] for b in await self.cartesian_product(L[1:])}
            return {(a, ) + b for a in L[0] for b in self.cartesian_product(L[1:])}
        else:
            return {()}

    # Handles unique fields by negoiating with the backend 
    def validate_unique_fields(self, params):
        #self.logger.info("IN THE UNIQUE FIELDS PLACE!")

        newlist = [params]
        if isinstance(params, list):
            #self.logger.info("ITS A LIST!")
            newlist = params

        # FIXME: Also handle MULTI PARAM
        values = []
        param_names = []
        all_values = {}
        index = 0
        for outerparam in newlist:

            #self.logger.info(f"INNERTYPE: {type(outerparam)}")
            #self.logger.info(f"HANDLING PARAM {key}")
            param_value = ""
            for key, value in outerparam.items():
                #self.logger.info("KEY: %s" % key)
                #value = params[key]
                for param in self.action["parameters"]:
                    try:
                        if param["name"] == key and param["unique_toggled"]:
                            self.logger.info(f"[DEBUG] FOUND: {key} with param {param}!")
                            if isinstance(value, dict) or isinstance(value, list):
                                try:
                                    value = json.dumps(value)
                                except json.decoder.JSONDecodeError as e:
                                    self.logger.info(f"[WARNING] Error in json decode for param {value}: {e}")
                                    continue
                            elif isinstance(value, int) or isinstance(value, float):
                                value = str(value)
                            elif value == False:
                                value = "False"
                            elif value == True:
                                value = "True"

                            self.logger.info(f"[DEBUG] VALUE APPEND: {value}")
                            param_value += value
                            if param["name"] not in param_names:
                                param_names.append(param["name"])

                    except (KeyError, NameError) as e:
                        self.logger.info(f"""Key/NameError in param handler for {param["name"]}: {e}""")

            #self.logger.info(f"[DEBUG] OUTER VALUE: {param_value}")
            if len(param_value) > 0:
                md5 = hashlib.md5(param_value.encode('utf-8')).hexdigest()
                values.append(md5)
                all_values[md5] = {
                    "index": index, 
                }

            index += 1

            # When in here, it means it should be unique
            # Should this be done by the backend? E.g. ask it if the value is valid?
            # 1. Check if it's unique towards key:value store in org for action
            # 2. Check if COMBINATION is unique towards key:value store of action for org
            # 3. Have a workflow configuration for unique ID's in unison or per field? E.g. if toggled, then send a hash of all fields together alphabetically, but if not, send one field at a time

            # org_id = full_execution["workflow"]["execution_org"]["id"]

            # USE ARRAY?

        new_params = []
        if len(values) > 0:
            org_id = self.full_execution["workflow"]["execution_org"]["id"]
            data = {
                "append": True,
                "workflow_check": False,
                "authorization": self.authorization,
                "execution_ref": self.current_execution_id,
                "org_id": org_id,
                "values": [{
                        "app": self.action["app_name"],
                        "action": self.action["name"],
                        "parameternames": param_names,
                        "parametervalues": values,
                }]
            }

            #self.logger.info(f"DATA: {data}")
            # 1594869a676630b397bc34f7dc0951a3

            url = f"{self.url}/api/v1/orgs/{org_id}/validate_app_values"
            ret = requests.post(url, json=data, verify=False, proxies=self.proxy_config)
            if ret.status_code == 200:
                json_value = ret.json()
                if len(json_value["found"]) > 0: 
                    modifier = 0
                    for item in json_value["found"]:
                        self.logger.info(f"Should remove {item}")

                        try:
                            self.logger.info(f"FOUND: {all_values[item]}")
                            self.logger.info(f"SHOULD REMOVE INDEX: {all_values[item]['index']}")

                            try:
                                newlist.pop(all_values[item]["index"]-modifier)
                                modifier += 1
                            except IndexError as e:
                                self.logger.info(f"Error popping value from array: {e}")
                        except (NameError, KeyError) as e:
                            self.logger.info(f"Failed removal: {e}")
                        
                            
                    #return False
                else:
                    self.logger.info("None of the items were found!")
                    return newlist
            else:
                self.logger.info(f"[WARNING] Failed checking values with status code {ret.status_code}!")

        #return True
        return newlist

    # Returns a list of all the executions to be done in the inner loop
    # FIXME: Doesn't take into account whether you actually WANT to loop or not
    # Check if the last part of the value is #?
    #async def get_param_multipliers(self, baseparams):
    def get_param_multipliers(self, baseparams):
        # Example:
        # {'call': ['hello', 'hello4'], 'call2': ['hello2', 'hello3'], 'call3': '1'}
        # 
        # Should become this because of pairs (all same-length arrays, PROBABLY indicates same source node's values.
        # [
        #   {'call': 'hello', 'call2': 'hello2', 'call3': '1'},
        #   {'call': 'hello4', 'call2': 'hello3', 'call3': '1'}
        # ] 
        # 
        # ----------------------------------------------------------------------
        # Example2:
        # {'call': ['hello'], 'call2': ['hello2', 'hello3'], 'call3': '1'}
        # 
        # Should become this because NOT pairs/triplets:
        # [
        #   {'call': 'hello', 'call2': 'hello2', 'call3': '1'},
        #   {'call': 'hello', 'call2': 'hello3', 'call3': '1'}
        # ] 
        # 
        # ----------------------------------------------------------------------
        # Example3:
        # {'call': ['hello', 'hello2'], 'call2': ['hello3', 'hello4', 'hello5'], 'call3': '1'}
        # 
        # Should become this because arrays are not same length, aka no pairs/triplets. This is the multiplier effect. 2x3 arrays = 6 iterations
        # [
        #   {'call': 'hello', 'call2': 'hello3', 'call3': '1'},
        #   {'call': 'hello', 'call2': 'hello4', 'call3': '1'},
        #   {'call': 'hello', 'call2': 'hello5', 'call3': '1'},
        #   {'call': 'hello2', 'call2': 'hello3', 'call3': '1'},
        #   {'call': 'hello2', 'call2': 'hello4', 'call3': '1'},
        #   {'call': 'hello2', 'call2': 'hello5', 'call3': '1'}
        # ] 
        # To achieve this, we'll do this:
        # 1. For the first array, take the total amount(y) (2x3=6) and divide it by the current array (x): 2. x/y = 3. This means do 3 of each value
        # 2. For the second array, take the total amount(y) (2x3=6) and divide it by the current array (x): 3. x/y = 2. 
        # 3. What does the 3rd array do? Same, but ehhh?
        # 
        # Example4:
        # What if there are multiple loops inside a single item?
        # 
        #

        paramlist = []
        listitems = []
        listlengths = []
        all_lists = []
        all_list_keys = []

        #check_value = "$Filter_list_testing.wrapper.#.tmp"
        #self.action = action

        loopnames = []
        self.logger.info(f"Baseparams to check: {baseparams}")
        for key, value in baseparams.items():
            check_value = ""
            for param in self.original_action["parameters"]:
                if param["name"] == key:
                    check_value = param["value"]
                    # self.result_wrapper_count = 0

                octothorpe_count = param["value"].count(".#")
                if octothorpe_count > self.result_wrapper_count:
                    self.result_wrapper_count = octothorpe_count
                    self.logger.info("[INFO] NEW OCTOTHORPE WRAPPER: %d" % octothorpe_count)


            # This whole thing is hard.
            # item = [{"data": "1.2.3.4", "dataType": "ip"}] 
            # $item         = DONT loop items. 
            # $item.#       = Loop items
            # $item.#.data  = Loop items
            # With a single item, this is fine.

            # item = [{"list": [{"data": "1.2.3.4", "dataType": "ip"}]}] 
            # $item                 = DONT loop items
            # $item.#               = Loop items
            # $item.#.list          = DONT loop items
            # $item.#.list.#        = Loop items
            # $item.#.list.#.data   = Loop items
            # If the item itself is a list.. hmm
            
            # FIXME: Check the above, and fix so that nested looped items can be 
            # Skipped if wanted

            #self.logger.info("\nCHECK: %s" % check_value)
            #try:
            #    values = parameter["value_replace"]
            #    if values != None:
            #        self.logger.info(values)
            #        for val in values:
            #            self.logger.info(val)
            #except:
            #    pass

            should_merge = False
            if "#" in check_value:
                should_merge = True

            # Specific for OpenAPI body replacement
            #self.logger.info("\n\n\nDOING STUFF BELOW HERE")
            if not should_merge:
                for parameter in self.original_action["parameters"]:
                    if parameter["name"] == key:
                        #self.logger.info("CHECKING BODY FOR VALUE REPLACE DATA!")
                        try:
                            values = parameter["value_replace"]
                            if values != None:
                                self.logger.info(values)
                                for val in values:
                                    if "#" in val["value"]:
                                        should_merge = True
                                        break
                        except:
                            pass

            #self.logger.info(f"VALUE LENGTH: {len(value)}")
            if isinstance(value, list):
                #subvalue = []
                # Override for single vs multi items
                #if len(value) > 0:
                #    if isinstance(value[0], list) and len(value[0]) == 1:
                #        subvalue = value[0]

                #    subvalue = value[0]


                if len(value) <= 1:
                    # FIXME: This broke some shit for a single item fml
                    # Necessary as override again :(
                    if len(value) == 1:
                        baseparams[key] = value[0]

                    #if "#" in check_value:
                    #    should_merge = True
                else:
                    #if len(value) > 1:
                    if not should_merge: 
                        self.logger.info("[DEBUG] Adding WITHOUT looping list")
                    else:
                        if len(value) not in listlengths:
                            listlengths.append(len(value))
                        #listlength

                        listitems.append(
                            {
                                key: len(value)
                            }
                        )
                        
                all_list_keys.append(key)
                all_lists.append(baseparams[key])
            else:
                #self.logger.info(f"{value} is not a list")
                pass

        self.logger.info("[DEBUG] Listlengths: %s - listitems: %d" % (listlengths, len(listitems)))
        #if len(listitems) == 0:
        if len(listlengths) == 0:
            self.logger.info("[DEBUG] NO multiplier. Running a single iteration.")
            paramlist.append(baseparams)

        #elif len(listitems) == 1:
        elif len(listlengths) == 1:
            self.logger.info("All subitems are the same length")

            for item in listitems:
                # This loops should always be length 1
                for key, value in item.items():
                    if not isinstance(value, int):
                        continue

                    if len(paramlist) == value:
                        for subloop in range(value):
                            baseitem = copy.deepcopy(baseparams)
                            paramlist[subloop][key] = baseparams[key][subloop]
                    else:
                        for subloop in range(value):
                            baseitem = copy.deepcopy(baseparams)
                            baseitem[key] = baseparams[key][subloop]
                            paramlist.append(baseitem)
                
        else:
            newlength = 1
            for item in listitems:
                for key, value in item.items():
                    newlength = newlength * value

            self.logger.info("[DEBUG] Newlength of array: %d. Lists: %s" % (newlength, all_lists))
            # Get the cartesian product of the arrays
            #cartesian = await self.cartesian_product(all_lists)
            try:
                cartesian = self.cartesian_product(all_lists)
                newlist = []
                for item in cartesian:
                    newlist.append(list(item))
            except Exception as e:
                self.logger.info(f"[ERROR] Error in cartesian product: {e}")
                newlist = []

            newobject = {}
            for subitem in range(len(newlist)):
                baseitem = copy.deepcopy(baseparams)
                for key in range(len(newlist[subitem])):
                    baseitem[all_list_keys[key]] = newlist[subitem][key]

                paramlist.append(baseitem)

            self.logger.info("CARTESIAN PARAMLIST: %s" % paramlist)

            #newlist[subitem[0]]
            #if len(newlist) > 0:
            #    itemlength = len(newlist[0])

            # How do we get it back, ordered?
            #for item in cartesian:
            #self.logger.info("Listlengths: %s" % listlengths)
            #paramlist = [baseparams]

        #self.logger.info("[INFO] Return paramlist (1): %s" % paramlist)
        return paramlist
            

    # Runs recursed versions with inner loops and such 
    #async def run_recursed_items(self, func, baseparams, loop_wrapper):
    def run_recursed_items(self, func, baseparams, loop_wrapper):
        self.logger.info(f"PRE RECURSED ITEMS: {baseparams}")
        has_loop = False

        newparams = {}
        for key, value in baseparams.items():
            if isinstance(value, list) and len(value) > 0:
                self.logger.info(f"[DEBUG] In list check for {key}")

                for value_index in range(len(value)):
                    try:
                        # Added skip for body (OpenAPI) which uses data= in requests
                        # Can be screwed up if they name theirs body too 
                        if key != "body":
                            value[value_index] = json.loads(value[value_index])
                    except json.decoder.JSONDecodeError as e:
                        pass
                    except TypeError as e:
                        pass

            try:
                #if isinstance(value, list) and len(value) == 1 and isinstance(value[0], list):
                #    try:
                #        loop_wrapper[key] += 1
                #    except Exception as e:
                #        self.logger.info(f"[WARNING] Exception in loop wrapper: {e}")
                #        loop_wrapper[key] = 1

                #    newparams[key] = value[0]
                #    has_loop = True 
                #else:
                    #self.logger.info(f"Key {key} is NOT a list within a list. Value: {value}")
                newparams[key] = value
            except Exception as e:
                self.logger.info(f"[WARNING] Error in baseparams list: {e}")
                newparams[key] = value
        
        results = []
        if has_loop:
            #self.logger.info(f"[DEBUG] Should run inner loop: {newparams}")
            self.logger.info(f"[DEBUG] Should run inner loop")
            #ret = await self.run_recursed_items(func, newparams, loop_wrapper)
            ret = self.run_recursed_items(func, newparams, loop_wrapper)
        else:
            self.logger.info(f"[DEBUG] Should run multiplier check with params (inner): {newparams}")
            #self.logger.info(f"[DEBUG] Should run multiplier check with params (inner)")

            # 1. Find the loops that are required and create new multipliers
            # If here: check for multipliers within this scope.
            ret = []
            param_multiplier = self.get_param_multipliers(newparams)

            #self.logger.info("PARAM MULTIPLIER: %s" % param_multiplier)

            # FIXME: This does a deduplication of the data
            new_params = self.validate_unique_fields(param_multiplier)
            if len(new_params) == 0:
                self.logger.info("[WARNING] SHOULD STOP MULTI-EXECUTION BECAUSE FIELDS AREN'T UNIQUE")
                self.action_result = {
                    "action": self.action,
                    "authorization": self.authorization,
                    "execution_id": self.current_execution_id,
                    "result": f"All {len(param_multiplier)} values were non-unique",
                    "started_at": self.start_time,
                    "status": "SKIPPED",
                    "completed_at": int(time.time_ns()),
                }

                self.send_result(self.action_result, {"Content-Type": "application/json", "Authorization": "Bearer %s" % self.authorization}, "/api/v1/streams")
                if runtime != "run":
                    exit()
                else:
                    return
            else:
                #subparams = new_params
                param_multiplier = new_params

            #self.logger.info(f"NEW PARAM MULTIPLIER: {param_multiplier}")

            #if isinstance(new_params, list) and len(new_params) == 1:
            #    params = new_params[0]
            #else:
            #    self.logger.info("[WARNING] SHOULD STOP EXECUTION BECAUSE FIELDS AREN'T UNIQUE")
            #    action_result["status"] = "SKIPPED"
            #    action_result["result"] = f"A non-unique value was found"  
            #    action_result["completed_at"] = int(time.time())
            #    self.send_result(action_result, headers, stream_path)
            #    return

            for subparams in param_multiplier:
                #self.logger.info(f"SUBPARAMS IN MULTI: {subparams}")
                tmp = ""
                try:

                    while True:
                        try:
                            tmp = func(**subparams)
                            break
                        except TypeError as e:
                            self.logger.info("BASE TYPEERROR: %s" % e)
                            errorstring = "%s" % e
                            if "got an unexpected keyword argument" in errorstring:
                                fieldsplit = errorstring.split("'")
                                if len(fieldsplit) > 1:
                                    field = fieldsplit[1]
                    
                                    try:
                                        del subparams[field]
                                        self.logger.info("Removed invalid field %s (1)" % field)
                                    except KeyError:
                                        break
                            else:
                                raise Exception(json.dumps({
                                    "success": False,
                                    "exception": f"TypeError: {e}",
                                    "reason": "You may be running an old version of this action. Please delete and remake the node.",
                                }))
                                break
                                

                except:
                    e = ""
                    try:
                        e = sys.exc_info()[1]
                    except:
                        self.logger.info("Exec check fail: %s" % e)
                        pass

                    tmp = json.dumps({
                        "success": False,
                        "reason": f"An error occured during the App Function Run (not Shuffle)",
                        "details": f"{e}",
                    })


                # An attempt at decomposing coroutine results
                # Backwards compatibility
                try:
                    if asyncio.iscoroutine(tmp):
                        self.logger.info("[DEBUG] In coroutine (2)")
                        async def parse_value(tmp):
                            value = await asyncio.gather(
                                tmp 
                            )

                            return value[0]


                        tmp = asyncio.run(parse_value(tmp))
                    else:
                        #self.logger.info("[DEBUG] Not in coroutine (2)")
                        pass
                except Exception as e:
                    self.logger.warning("[ERROR] Failed to parse coroutine value for old app: {e}")

                new_value = tmp
                if tmp == None:
                    new_value = ""
                elif isinstance(tmp, dict):
                    new_value = json.dumps(tmp)
                elif isinstance(tmp, list):
                    new_value = json.dumps(tmp)
                #else:
                #tmp = tmp.replace("\"", "\\\"", -1)

                try:
                    new_value = json.loads(new_value)
                except json.decoder.JSONDecodeError as e:
                    pass
                except TypeError as e:
                    pass
                except:
                    pass
                        #self.logger.info("Json: %s" % e)
                        #ret.append(tmp)
                
                #if self.result_wrapper_count > 0:
                #    ret.append("["*(self.result_wrapper_count-1)+new_value+"]"*(self.result_wrapper_count-1))
                #else:
                ret.append(new_value)

            self.logger.info("[INFO] Function return length: %d" % len(ret))
            if len(ret) == 1:
                #ret = ret[0]
                self.logger.info("[DEBUG] DONT make list of 1 into 0!!")

        #self.logger.info("Return from execution: %s" % ret)
        if ret == None:
            results.append("")
            json_object = False
        elif isinstance(ret, dict):
            results.append(ret)
            json_object = True
        elif isinstance(ret, list):
            results = ret
            json_object = True
        else:
            ret = ret.replace("\"", "\\\"", -1)

            try:
                results.append(json.loads(ret))
                json_object = True
            except json.decoder.JSONDecodeError as e:
                #self.logger.info("Json: %s" % e)
                results.append(ret)
            except TypeError as e:
                results.append(ret)
            except:
                results.append(ret)

        #if len(results) == 1: 
        #    #results = results[0]
        #    #self.logger.info("DONT MAKE LIST FROM 1 TO 0!!")
        #    pass

        #self.logger.info("\nLOOP: %s\nRESULTS: %s" % (loop_wrapper, results))
        return results

    # Downloads all files from a namespace
    # Currently only working on local version of Shuffle (2023)
    def get_file_category_ids(self, category):
        org_id = self.full_execution["workflow"]["execution_org"]["id"]

        get_path = "/api/v1/files/namespaces/%s?execution_id=%s&ids=true" % (category, self.full_execution["execution_id"])
        headers = {
            "Authorization": "Bearer %s" % self.authorization,
            "User-Agent": "Shuffle 1.1.0",
        }

        ret = requests.get("%s%s" % (self.url, get_path), headers=headers, verify=False, proxies=self.proxy_config)
        return ret.json()
        #if ret1.status_code != 200:
        #    return {
        #        "success": False,
        #        "reason": "Status code is %d from backend for category %s" % category,
        #        "list": [],
        #    }

        #return {
        #    "success": True,
        #    "ids": ret1.json(),
        #}


    # Downloads all files from a namespace
    # Currently only working on local version of Shuffle
    def get_file_namespace(self, namespace):
        org_id = self.full_execution["workflow"]["execution_org"]["id"]

        get_path = "/api/v1/files/namespaces/%s?execution_id=%s" % (namespace, self.full_execution["execution_id"])
        headers = {
            "Authorization": "Bearer %s" % self.authorization,
            "User-Agent": "Shuffle 1.1.0",
        }

        ret1 = requests.get("%s%s" % (self.url, get_path), headers=headers, verify=False, proxies=self.proxy_config)
        if ret1.status_code != 200:
            return None 

        filebytes = BytesIO(ret1.content)
        myzipfile = zipfile.ZipFile(filebytes)

        # Unzip and build here!
        #for member in files.namelist():
        #    filename = os.path.basename(member)
        #    if not filename:
        #        continue

        #    self.logger.info("File: %s" % member)
        #    source = files.open(member)
        #    with open("%s/%s" % (basedir, source.name), "wb+") as tmp:
        #        filedata = source.read()
        #        self.logger.info("Filedata (%s): %s" % (source.name, filedata))
        #        tmp.write(filedata)

        return myzipfile

    def get_file_namespace_ids(self, namespace):
        return self.get_file_category_ids(self, namespace)

    def get_file_category(self, category):
        return self.get_file_namespace(self, category)

    # Things to consider for files:
    # - How can you download / stream a file? 
    # - Can you decide if you want a stream or the files directly?
    def get_file(self, value):
        full_execution = self.full_execution
        org_id = full_execution["workflow"]["execution_org"]["id"]

        if isinstance(value, list):
            self.logger.info("IS LIST!")
            #if len(value) == 1:
            #    value = value[0]
        else:
            value = [value]

        returns = []
        for item in value:
            self.logger.info("FILE VALUE: %s" % item)
            # Check if item is a dict, and if it is, check if it has the key "id"
            if isinstance(item, dict):
                if "file_id" in item: 
                    item = item["file_id"]
                elif "id" in item:
                    item = item["id"]

            if len(item) != 36 and not item.startswith("file_"):
                self.logger.info("Bad length for file value: '%s'" % item)
                continue
                #return {
                #    "filename": "",
                #    "data": "",
                #    "success": False,
                #}

            get_path = "/api/v1/files/%s?execution_id=%s" % (item, full_execution["execution_id"])
            headers = {
                "Content-Type": "application/json",     
                "Authorization": "Bearer %s" % self.authorization,
                "User-Agent": "Shuffle 1.1.0",
            }

            ret1 = requests.get("%s%s" % (self.url, get_path), headers=headers, verify=False, proxies=self.proxy_config)
            if ret1.status_code != 200:
                returns.append({
                    "filename": "",
                    "data": "",
                    "success": False,
                })
                continue

            content_path = "/api/v1/files/%s/content?execution_id=%s" % (item, full_execution["execution_id"])
            ret2 = requests.get("%s%s" % (self.url, content_path), headers=headers, verify=False, proxies=self.proxy_config)
            if ret2.status_code == 200:
                tmpdata = ret1.json()
                returndata = {
                    "success": True,
                    "filename": tmpdata["filename"],
                    "data": ret2.content,
                }
                returns.append(returndata)

        if len(returns) == 0:
            return {
                "success": False,
                "filename": "",
                "data": b"",
            }
        elif len(returns) == 1:
            return returns[0]
        else:
            return returns

    def delete_cache(self, key):
        org_id = self.full_execution["workflow"]["execution_org"]["id"]
        url = "%s/api/v1/orgs/%s/delete_cache" % (self.url, org_id)

        data = {
            "workflow_id": self.full_execution["workflow"]["id"],
            "execution_id": self.current_execution_id,
            "authorization": self.authorization,
            "org_id": org_id,
            "key": key,
        }

        try:
            newstorage = []
            for item in self.local_storage:
                if item["execution_id"] == self.current_execution_id and item["key"] == key:
                    continue

                newstorage.append(item)

            self.local_storage = newstorage

        except Exception as e:
            print("[ERROR] Failed DELETING current execution id local storage: %s" % e)

        response = requests.post(url, json=data, verify=False, proxies=self.proxy_config)
        try:
            allvalues = response.json()
            return json.dumps(allvalues)
        except Exception as e:
            self.logger.info("[ERROR} Failed to parse response from delete_cache: %s" % e)
            #return response.json()
            return json.dumps({"success": False, "reason": f"Failed to delete cache for key '{key}'"})

    def set_cache(self, key, value):
        org_id = self.full_execution["workflow"]["execution_org"]["id"]
        url = "%s/api/v1/orgs/%s/set_cache" % (self.url, org_id)
        data = {
            "workflow_id": self.full_execution["workflow"]["id"],
            "execution_id": self.current_execution_id,
            "authorization": self.authorization,
            "org_id": org_id,
            "key": key,
            "value": str(value),
        }

        try:
            newstorage = []
            for item in self.local_storage:
                if item["execution_id"] == self.current_execution_id and item["key"] == key:
                    continue

                newstorage.append(item)

            self.local_storage = newstorage

        except Exception as e:
            print("[ERROR] Failed SETTING current execution id local storage: %s" % e)

        response = requests.post(url, json=data, verify=False, proxies=self.proxy_config)
        try:
            allvalues = response.json()
            allvalues["key"] = key
            allvalues["value"] = str(value)
            return allvalues
        except Exception as e:
            self.logger.info("[ERROR} Failed to parse response from set cache: %s" % e)
            #return response.json()
            return {"success": False}

    def get_cache(self, key):
        org_id = self.full_execution["workflow"]["execution_org"]["id"]
        url = "%s/api/v1/orgs/%s/get_cache" % (self.url, org_id)
        data = {
            "workflow_id": self.full_execution["workflow"]["id"],
            "execution_id": self.current_execution_id,
            "authorization": self.authorization,
            "org_id": org_id,
            "key": key,
        }

        # Makes it so that loops for the same action doesn't re-ask the db unless necessary
        try:
            for item in self.local_storage:
                if item["execution_id"] == self.current_execution_id and item["key"] == key:
                    # Max keeping the local cache properly for 5 seconds due to workflow continuations
                    elapsed_time = time.time() - item["time_set"]
                    if elapsed_time > 5:
                        break

                    return item["data"]
        except Exception as e:
            print("[ERROR] Failed getting current execution id local storage: %s" % e)

        value = requests.post(url, json=data, verify=False, proxies=self.proxy_config)
        try:
            allvalues = value.json()
            allvalues["key"] = key 

            try:
                parsedvalue = json.loads(allvalues["value"])
                allvalues["value"] = parsedvalue
            except:
                self.logger.info("Parsing of value as JSON failed. Continue anyway!")

            try:
                newdata = json.loads(json.dumps(data))
                newdata["time_set"] = time.time()
                newdata["data"] = allvalues
                self.local_storage.append(newdata)
            except Exception as e:
                print("[ERROR] Failed in local storage append: %s" % e)

            return allvalues
        except:
            self.logger.info("Value couldn't be parsed, or json dump of value failed")
            #return value.json()
            return {"success": False}

    # Wrapper for set_files
    def set_file(self, infiles):
        return self.set_files(infiles)

    # Sets files in the backend
    def set_files(self, infiles):
        full_execution = self.full_execution
        workflow_id = full_execution["workflow"]["id"]
        org_id = full_execution["workflow"]["execution_org"]["id"]
        headers = {
            "Content-Type": "application/json",     
            "Authorization": "Bearer %s" % self.authorization,
            "User-Agent": "Shuffle 1.1.0",
        }

        if not isinstance(infiles, list):
            infiles = [infiles]

        create_path = "/api/v1/files/create?execution_id=%s" % full_execution["execution_id"]
        file_ids = []
        for curfile in infiles:
            filename = "unspecified"
            data = {
                "filename": filename,
                "workflow_id": workflow_id,
                "org_id": org_id,
            }

            try:
                data["filename"] = curfile["filename"]
                filename = curfile["filename"]
            except KeyError as e:
                self.logger.info(f"KeyError in file setup: {e}")
                pass

            ret = requests.post("%s%s" % (self.url, create_path), headers=headers, json=data, verify=False, proxies=self.proxy_config)
            #self.logger.info(f"Ret CREATE: {ret.text}")
            cur_id = ""
            if ret.status_code == 200:
                ret_json = ret.json()
                if not ret_json["success"]:
                    self.logger.info("Not success in file upload creation.")
                    continue

                self.logger.info("Should handle ID %s" % ret_json["id"])
                file_ids.append(ret_json["id"])
                cur_id = ret_json["id"]
            else:
                self.logger.info("Bad status code: %d" % ret.status_code)
                continue

            if len(cur_id) == 0:
                self.logger.info("No file ID specified from backend")
                continue

            new_headers = {
                "Authorization": f"Bearer {self.authorization}",
                "User-Agent": "Shuffle 1.1.0",
            }

            upload_path = "/api/v1/files/%s/upload?execution_id=%s" % (cur_id, full_execution["execution_id"])

            files={"shuffle_file": (filename, curfile["data"])}
            #open(filename,'rb')}

            ret = requests.post("%s%s" % (self.url, upload_path), files=files, headers=new_headers, verify=False, proxies=self.proxy_config)

        return file_ids
    
    #async def execute_action(self, action):
    def execute_action(self, action):
        # !!! Let this line stay - its used for some horrible codegeneration / stitching !!! # 
        #STARTCOPY
        stream_path = "/api/v1/streams"
        self.action_result = {
            "action": action,
            "authorization": self.authorization,
            "execution_id": self.current_execution_id,
            "result": "",
            "started_at": int(time.time_ns()),
            "status": "EXECUTING"
        }

        # Simple validation of parameters in general
        replace_params = False
        try:
            tmp_parameters = action["parameters"]
            for param in tmp_parameters:
                if param["value"] == "SHUFFLE_AUTO_REMOVED":
                    replace_params = True
        except KeyError:
            action["parameters"] = []
        except TypeError:
            pass

        self.action = copy.deepcopy(action)

        headers = {
            "Content-Type": "application/json",     
            "Authorization": f"Bearer {self.authorization}",
            "User-Agent": "Shuffle 1.1.0",
        }

        if len(self.action) == 0:
            self.logger.info("[WARNING] ACTION env not defined")
            self.action_result["result"] = "Error in setup ENV: ACTION not defined"
            self.send_result(self.action_result, headers, stream_path) 
            return

        if len(self.authorization) == 0:
            self.logger.info("[WARING] AUTHORIZATION env not defined")
            self.action_result["result"] = "Error in setup ENV: AUTHORIZATION not defined"
            self.send_result(self.action_result, headers, stream_path) 
            return

        if len(self.current_execution_id) == 0:
            self.logger.info("[WARNING] EXECUTIONID env not defined")
            self.action_result["result"] = "Error in setup ENV: EXECUTIONID not defined"
            self.send_result(self.action_result, headers, stream_path) 
            return


        # Add async logger
        # self.console_logger.handlers[0].stream.set_execution_id()

        # FIXME: Shouldn't skip this, but it's good for minimzing API calls
        #try:
        #    ret = requests.post("%s%s" % (self.base_url, stream_path), headers=headers, json=action_result, verify=False)
        #    self.logger.info("Workflow: %d" % ret.status_code)
        #    if ret.status_code != 200:
        #        self.logger.info(ret.text)
        #except requests.exceptions.ConnectionError as e:
        #    self.logger.info("Connectionerror: %s" %  e)

        #    action_result["result"] = "Bad setup during startup: %s" % e 
        #    self.send_result(action_result, headers, stream_path) 
        #    return

        # Verify whether there are any parameters with ACTION_RESULT required
        # If found, we get the full results list from backend
        fullexecution = {}
        if isinstance(self.full_execution, str) and len(self.full_execution) == 0:
            #self.logger.info("[DEBUG] NO EXECUTION - LOADING!")
            try:
                failed = False
                rettext = ""
                for i in range(0, 5):
                    tmpdata = {
                        "authorization": self.authorization,
                        "execution_id": self.current_execution_id
                    }

                    resultsurl = "%s/api/v1/streams/results" % (self.base_url)
                    ret = requests.post(
                        resultsurl,
                        headers=headers, 
                        json=tmpdata,
                        verify=False,
                        proxies=self.proxy_config,
                    )

                    if ret.status_code == 200:
                        fullexecution = ret.json()
                        failed = False
                        break

                    #elif ret.status_code == 500 or ret.status_code == 400:
                    elif ret.status_code >= 400:
                        self.logger.info("[ERROR] (fails: %d) Error in app with status code %d for results (1). RETRYING because results can't be handled" % (i+1, ret.status_code))
                    
                        rettext = ret.text
                        failed = True 
                        time.sleep(8)
                        continue

                    else:
                        self.logger.info("[ERROR] (fails: %d) Error in app with status code %d for results (2). Crashing because results can't be handled. Details: %s" % (i+1, ret.status_code, ret.text))

                        rettext = ret.text
                        failed = True 
                        time.sleep(8)
                        break

                if failed:
                    self.action_result["result"] = json.dumps({
                        "success": False,
                        "reason": f"Bad result from backend during startup of app: {ret.status_code}",
                        "extended_reason": f"{rettext}"
                    })

                    self.send_result(self.action_result, headers, stream_path) 
                    return

            except requests.exceptions.ConnectionError as e:
                self.logger.info("[ERROR] FullExec Connectionerror: %s" %  e)
                self.action_result["result"] = json.dumps({
                    "success": False,
                    "reason": f"Connection error during startup (connection error): {e}"
                })

                self.send_result(self.action_result, headers, stream_path) 
                return
            except Exception as e:
                self.logger.info("[ERROR] FullExec Exception outer: %s" %  e)
                self.action_result["result"] = json.dumps({
                    "success": False,
                    "reason": f"Exception during startup of app (general error): {e}"
                })

                self.send_result(self.action_result, headers, stream_path) 
                return

        else:
            self.logger.info(f"[DEBUG] Setting execution to default value with type {type(self.full_execution)}")
            try:
                fullexecution = json.loads(self.full_execution)
            except json.decoder.JSONDecodeError as e:
                self.logger.info("[ERROR] Json decode execution error: %s" % e)  
                self.action_result["result"] = "Json error during startup: %s" % e
                self.send_result(self.action_result, headers, stream_path) 
                return

            self.logger.info("")


        self.full_execution = fullexecution

        found_id = ""
        try:
            if "execution_id" in self.full_execution and len(self.full_execution["execution_id"]) > 0:
                found_id = self.full_execution["execution_id"]
            elif len(self.current_execution_id) > 0:
                found_id = self.current_execution_id
        except Exception as e:
            print("[ERROR] Failed in get full exec")
                
        try:
            contains_body = False
            parameter_count = 0

            if "parameters" in self.action:
                parameter_count = len(self.action["parameters"])
                for param in self.action["parameters"]:
                    if param["name"] == "body":
                        contains_body = True

            print("[DEBUG][%s] Action name: %s, Params: %d, Has Body: %s" % (self.current_execution_id, self.action["name"], parameter_count, str(contains_body)))
        except Exception as e:
            print("[ERROR] Failed in init print handler: %s" % e)

        try:
            if replace_params == True:
                for inner_action in self.full_execution["workflow"]["actions"]:
                    self.logger.info("[DEBUG] ID: %s vs %s" % (inner_action["id"], self.action["id"]))

                    # In case of some kind of magic, we're just doing params
                    if inner_action["id"] != self.action["id"]:
                        continue
                        self.logger.info("FOUND!")

                        if isinstance(self.action, str):
                            self.logger.info("Params is in string object for self.action?")
                        else:
                            self.action["parameters"] = inner_action["parameters"]
                            self.action_result["action"]["parameters"] = inner_action["parameters"]

                        if isinstance(self.original_action, str):
                            self.logger.info("Params for original actions is in string object?")
                        else:
                            self.original_action["parameters"] = inner_action["parameters"]

                        break

        except Exception as e:
            self.logger.info(f"[WARNING] Failed in replace params action parsing: {e}")

        # Gets the value at the parenthesis level you want
        def parse_nested_param(string, level):
            """
            Generate strings contained in nested (), indexing i = level
            """
            if len(re.findall("\(", string)) == len(re.findall("\)", string)):
                LeftRightIndex = [x for x in zip(
                [Left.start()+1 for Left in re.finditer('\(', string)], 
                reversed([Right.start() for Right in re.finditer('\)', string)]))]
        
            elif len(re.findall("\(", string)) > len(re.findall("\)", string)):
                return parse_nested_param(string + ')', level)
            elif len(re.findall("\(", string)) < len(re.findall("\)", string)):
                return parse_nested_param('(' + string, level)
            else:
                return 'Failed to parse params'
        
            try:
                return [string[LeftRightIndex[level][0]:LeftRightIndex[level][1]]]
            except IndexError:
                return [string[LeftRightIndex[level+1][0]:LeftRightIndex[level+1][1]]]
        
        # Finds the deepest level parenthesis in a string
        def maxDepth(S): 
            current_max = 0
            max = 0
            n = len(S) 
          
            # Traverse the input string 
            for i in range(n): 
                if S[i] == '(': 
                    current_max += 1
          
                    if current_max > max: 
                        max = current_max 
                elif S[i] == ')': 
                    if current_max > 0: 
                        current_max -= 1
                    else: 
                        return -1
          
            # finally check for unbalanced string 
            if current_max != 0: 
                return -1
          
            return max-1
        
        # Specific type parsing
        def parse_type(data, thistype): 
            if data == None:
                return "Empty"
        
            if "int" in thistype or "number" in thistype:
                try:
                    return int(data)
                except ValueError:
                    return data

            if "lower" in thistype:
                return data.lower()
            if "upper" in thistype:
                return data.upper()
            if "trim" in thistype:
                return data.strip()
            if "strip" in thistype:
                return data.strip()
            if "split" in thistype:
                return data.split()
            if "replace" in thistype:
                splitvalues = data.split(",")

                if len(splitvalues) > 2:
                    for i in range(len(splitvalues)):
                        if i != 0:
                            if splitvalues[i] == "  ":
                                splitvalues[i] = " "
                                continue

                            splitvalues[i] = splitvalues[i].strip()

                            if splitvalues[i] == "\"\"":
                                splitvalues[i] = ""
                            if splitvalues[i] == "\" \"":
                                splitvalues[i] = " "
                            if len(splitvalues[i]) > 2:
                                if splitvalues[i][0] == "\"" and splitvalues[i][len(splitvalues[i])-1] == "\"":
                                    splitvalues[i] = splitvalues[i][1:-1]
                                if splitvalues[i][0] == "'" and splitvalues[i][len(splitvalues[i])-1] == "'":
                                    splitvalues[i] = splitvalues[i][1:-1]
                            

                    replacementvalue = splitvalues[0]
                    return replacementvalue.replace(splitvalues[1], splitvalues[2], -1) 
                else: 
                    return f"replace({data})"
            if "join" in thistype:
                try:
                    splitvalues = data.split(",")
                    if "," not in data:
                        return f"join({data})"

                    if len(splitvalues) >= 2:

                        # 1. Take the list and parse it from string
                        # 2. Take all the items and join them
                        # 3. Parse them back as string and return
                        values = ",".join(splitvalues[0:-1])
                        tmp = json.loads(values)
                        try:
                            newvalues = splitvalues[-1].join(str(item).strip() for item in tmp)
                        except TypeError:
                            newvalues = splitvalues[-1].join(json.dumps(item).strip() for item in tmp)

                        return newvalues
                    else:
                        return f"join({data})"

                except (KeyError, IndexError) as e:
                    pass
                except json.decoder.JSONDecodeError as e:
                    pass

            if "len" in thistype or "length" in thistype or "lenght" in thistype:
                #self.logger.info(f"Trying to length-parse: {data}")
                try:
                    tmp_len = json.loads(data, parse_float=str, parse_int=str, parse_constant=str)
                except (NameError, KeyError, TypeError, json.decoder.JSONDecodeError) as e:
                    try:
                        #self.logger.info(f"[WARNING] INITIAL Parsing bug for length in app sdk: {e}")
                        # data = data.replace("\'", "\"")
                        data = data.replace("True", "true", -1)
                        data = data.replace("False", "false", -1)
                        data = data.replace("None", "null", -1)
                        data = data.replace("\"", "\\\"", -1)
                        data = data.replace("'", "\"", -1)

                        tmp_len = json.loads(data, parse_float=str, parse_int=str, parse_constant=str)
                    except (NameError, KeyError, TypeError, json.decoder.JSONDecodeError) as e:
                        tmp_len = str(data)

                return str(len(tmp_len))

            if "parse" in thistype:
                splitvalues = []
                default_error = """Error. Expected syntax: parse(["hello","test1"],0:1)""" 
                if "," in data:
                    splitvalues = data.split(",")

                    for item in range(len(splitvalues)):
                        splitvalues[item] = splitvalues[item].strip()
                else:
                    return default_error 

                lastsplit = []
                if ":" in splitvalues[-1]:
                    lastsplit = splitvalues[-1].split(":")
                else:
                    try:
                        lastsplit = [int(splitvalues[-1])]
                    except ValueError:
                        return default_error

                try:
                    parsedlist = ",".join(splitvalues[0:-1])
                    if len(lastsplit) > 1:
                        tmp = json.loads(parsedlist)[int(lastsplit[0]):int(lastsplit[1])]
                    else:
                        tmp = json.loads(parsedlist)[lastsplit[0]]

                    return tmp
                except IndexError as e:
                    return default_error

        # Parses the INNER value and recurses until everything is done
        # Looks for a way to use e.g. int() or number() as a value
        def parse_wrapper(data):
            try:
                if "(" not in data or ")" not in data:
                    return data, False
            except TypeError:
                return data, False

            # Because liquid can handle ALL of this now.
            # Implemented for >0.9.25
            #self.logger.info("[DEBUG] Skipping parser because use of its been deprecated >0.9.25 due to Liquid implementation")
            return data, False

            wrappers = ["int", "number", "lower", "upper", "trim", "strip", "split", "parse", "len", "length", "lenght", "join", "replace"]

            if not any(wrapper in data for wrapper in wrappers):
                return data, False

            # Do stuff here.
            inner_value = parse_nested_param(data, maxDepth(data) - 0)
            outer_value = parse_nested_param(data, maxDepth(data) - 1)

            wrapper_group = "|".join(wrappers)
            parse_string = data
            max_depth = maxDepth(parse_string)

            if outer_value != inner_value:
                for casting_items in reversed(range(max_depth + 1)):
                    c_parentheses = parse_nested_param(parse_string, casting_items)[0]
                    match_string = re.escape(c_parentheses)
                    custom_casting = re.findall(fr"({wrapper_group})\({match_string}", parse_string)

                    # no matching ; go next group
                    if len(custom_casting) == 0:
                        continue

                    inner_result = parse_type(c_parentheses, custom_casting[0])

                    # if result is a string then parse else return
                    if isinstance(inner_result, str):
                        parse_string = parse_string.replace(f"{custom_casting[0]}({c_parentheses})", inner_result, 1)
                    elif isinstance(inner_result, list):
                        parse_string = parse_string.replace(f"{custom_casting[0]}({c_parentheses})", json.dumps(inner_result), 1)
                    else:
                        parse_string = inner_result
                        break
            else:
                c_parentheses = parse_nested_param(parse_string, 0)[0]
                match_string = re.escape(c_parentheses)
                custom_casting = re.findall(fr"({wrapper_group})\({match_string}", parse_string)
                # check if a wrapper was found
                if len(custom_casting) != 0:
                    inner_result = parse_type(c_parentheses, custom_casting[0])
                    if isinstance(inner_result, str):
                        parse_string = parse_string.replace(f"{custom_casting[0]}({c_parentheses})", inner_result)
                    elif isinstance(inner_result, list):
                        parse_string = parse_string.replace(f"{custom_casting[0]}({c_parentheses})",
                                                            json.dumps(inner_result))
                    else:
                        parse_string = inner_result

            return parse_string, True

        # Looks for parantheses to grab special cases within a string, e.g:
        # int(1) lower(HELLO) or length(what's the length)
        # FIXME: 
        # There is an issue in here where it returns data wrong. Example:
        # Authorization=Bearer authkey
        # =
        # Authorization=Bearer  authkey
        # ^ Double space.
        def parse_wrapper_start(data, self):
            try:
                data = parse_liquid(data, self)
            except:
                pass

            if "(" not in data or ")" not in data:
                return data

            if isinstance(data, str) and len(data) > 4:
                if (data[0] == "{" or data[0] == "[") and (data[len(data)-1] == "]" or data[len(data)-1] == "}"):
                    self.logger.info("[DEBUG] Skipping parser because use of {[ and ]}")
                    return data

            newdata = []
            newstring = ""
            record = True
            paranCnt = 0
            charcnt = 0 
            for char in data:
                if char == "(":
                    charskip = False
                    if charcnt > 0:
                        if data[charcnt-1] == " ":
                            charskip = True 

                    if not charskip:
                        paranCnt += 1
            
                        if not record:
                            record = True 
        
                if record:
                    newstring += char
        
                if paranCnt == 0 and char == " ":
                    newdata.append(newstring)
                    newstring = ""
                    record = True
        
                if char == ")":
                    paranCnt -= 1
        
                    if paranCnt == 0:
                        record = False
            
                charcnt += 1
        
            if len(newstring) > 0:
                newdata.append(newstring)
        
            parsedlist = []
            non_string = False
            parsed = False
            for item in newdata:
                ret = parse_wrapper(item)
                if not isinstance(ret[0], str):
                    non_string = True
            
                parsedlist.append(ret[0])
                if ret[1]:
                    parsed = True
            
            if not parsed:
                return data
        
            if len(parsedlist) > 0 and not non_string:
                #self.logger.info("Returning parsed list: ", parsedlist)
                return " ".join(parsedlist)
            elif len(parsedlist) == 1 and non_string:
                return parsedlist[0]
            else:
                #self.logger.info("Casting back to string because multi: ", parsedlist)
                newlist = []
                for item in parsedlist:
                    try:
                        newlist.append(str(item))
                    except ValueError:
                        newlist.append("parsing_error")

                # Does this create the issue?
                return " ".join(newlist)

        # Parses JSON loops and such down to the item you're looking for
        # Check recurse_test.py for examples and tests of this function
        # $nodename.#.id 
        # $nodename.data.#min-max.info.id
        # $nodename.data.#1-max.info.id
        # $nodename.data.#min-1.info.id
        def recurse_json(basejson, parsersplit):
            match = "#([0-9a-z]+):?-?([0-9a-z]+)?#?"
            try:
                outercnt = 0

                # Loops over split values
                splitcnt = -1 
                for value in parsersplit:
                    splitcnt += 1
                    #if " " in value:
                    #    value = value.replace(" ", "_", -1)

                    actualitem = re.findall(match, value, re.MULTILINE)
                    # Goes here if loop 
                    if value == "#":
                        newvalue = []

                        if basejson == None:
                            return "", False

                        for innervalue in basejson:
                            # 1. Check the next item (message)
                            # 2. Call this function again

                            try:
                                ret, is_loop = recurse_json(innervalue, parsersplit[outercnt+1:])
                            except IndexError:
                                # Only in here if it's the last loop without anything in it?
                                ret, is_loop = recurse_json(innervalue, parsersplit[outercnt:])
                                
                            newvalue.append(ret)
                        
                        # Magical way of returning which makes app sdk identify 
                        # it as multi execution
                        return newvalue, True

                    # Checks specific regex like #1-2 for index 1-2 in a loop
                    elif len(actualitem) > 0:

                        is_loop = True
                        newvalue = []
                        firstitem = actualitem[0][0]
                        seconditem = actualitem[0][1]
                        if isinstance(firstitem, int):
                            firstitem = str(firstitem)
                        if isinstance(seconditem, int):
                            seconditem = str(seconditem)

                        # Means it's a single item -> continue
                        if seconditem == "":
                            if str(firstitem).lower() == "max" or str(firstitem).lower() == "last" or str(firstitem).lower() == "end": 
                                firstitem = len(basejson)-1
                            elif str(firstitem).lower() == "min" or str(firstitem).lower() == "first": 
                                firstitem = 0
                            else:
                                firstitem = int(firstitem)

                            tmpitem = basejson[int(firstitem)]
                            try:
                                newvalue, is_loop = recurse_json(tmpitem, parsersplit[outercnt+1:])
                            except IndexError:
                                newvalue, is_loop = (tmpitem, parsersplit[outercnt+1:])
                        else:
                            if isinstance(firstitem, str):
                                if firstitem.lower() == "max" or firstitem.lower() == "last" or firstitem.lower() == "end": 
                                    firstitem = len(basejson)-1
                                elif firstitem.lower() == "min" or firstitem.lower() == "first": 
                                    firstitem = 0
                                else:
                                    firstitem = int(firstitem)
                            else:
                                firstitem = int(firstitem)

                            if isinstance(seconditem, str): 
                                if str(seconditem).lower() == "max" or str(seconditem).lower() == "last" or str(firstitem).lower() == "end": 
                                    seconditem = len(basejson)-1
                                elif str(seconditem).lower() == "min" or str(seconditem).lower() == "first": 
                                    seconditem = 0
                                else:
                                    seconditem = int(seconditem)
                            else:
                                seconditem = int(seconditem)

                            newvalue = []
                            if int(seconditem) > len(basejson):
                                seconditem = len(basejson)

                            for i in range(int(firstitem), int(seconditem)+1):
                                # 1. Check the next item (message)
                                # 2. Call this function again

                                try:
                                    ret, tmp_loop = recurse_json(basejson[i], parsersplit[outercnt+1:])
                                except IndexError:
                                    #ret = innervalue
                                    ret, tmp_loop = recurse_json(basejson[i], parsersplit[outercnt:])
                                    
                                newvalue.append(ret)

                        return newvalue, is_loop 

                    else:
                        if len(value) == 0:
                            return basejson, False

                        try:
                            if isinstance(basejson, list): 
                                return basejson, False
                            elif isinstance(basejson, bool):
                                return basejson, False
                            elif isinstance(basejson, int):
                                return basejson, False
                            elif isinstance(basejson[value], str):
                                try:
                                    if (basejson[value].endswith("}") and basejson[value].endswith("}")) or (basejson[value].startswith("[") and basejson[value].endswith("]")):
                                        basejson = json.loads(basejson[value])
                                    else:
                                        # Should we sanitize here?
                                        # Check if we are on the last item?
                                        if outercnt == len(parsersplit)-1:
                                            return str(basejson[value]), False
                                        else:
                                            pass

                                except json.decoder.JSONDecodeError as e:
                                    return str(basejson[value]), False
                            else:
                                basejson = basejson[value]
                        except KeyError as e:
                            if "_" in value:
                                value = value.replace("_", " ", -1)
                            elif " " in value:
                                value = value.replace(" ", "_", -1)

                            try:
                                if isinstance(basejson, list): 
                                    return basejson, False
                                elif isinstance(basejson, bool):
                                    return basejson, False
                                elif isinstance(basejson, int):
                                    return basejson, False
                                elif isinstance(basejson[value], str):
                                    try:
                                        if (basejson[value].endswith("}") and basejson[value].endswith("}")) or (basejson[value].startswith("[") and basejson[value].endswith("]")):
                                            basejson = json.loads(basejson[value])
                                        else:

                                            if outercnt == len(parsersplit)-1:
                                                return str(basejson[value]), False
                                            else:
                                                pass

                                    except json.decoder.JSONDecodeError as e:
                                        return str(basejson[value]), False
                                else:
                                    basejson = basejson[value]
                            except KeyError as e:
                                # Check if previous key was handled or not
                                previouskey = parsersplit[outercnt-1]

                                tmpval = previouskey + "." + value
                                if tmpval in basejson:
                                    return basejson[tmpval], False

                                try:
                                    currentsplitcnt = splitcnt 

                                    recursed_value = value
                                    handled = False

                                    #tmpbase = basejson
                                    previouskey = value
                                    while True:
                                        newvalue = parsersplit[currentsplitcnt+1]
                                        if newvalue == "#" or newvalue == "":
                                            break 

                                        recursed_value += "." + newvalue

                                        found = False
                                        for key, value in basejson.items():
                                            if recursed_value.lower() in key.lower(): 
                                                found = True

                                        if found == False:
                                            # Check if we are on the last key or not
                                            return "", False

                                        if recursed_value in basejson:
                                            basejson = basejson[recursed_value]

                                            # Whether to dig deeper or not
                                            if isinstance(basejson, bool) or isinstance(basejson, int) or isinstance(basejson, str):
                                                handled = False 
                                            else:
                                                handled = True 

                                            break

                                        currentsplitcnt += 1

                                    if handled:
                                        continue
                                    
                                    break
                                except IndexError as e:
                                    return "", False

                    outercnt += 1

            except KeyError as e:
                return "", False
            except Exception as e:
                return "", False

            return basejson, False

        # Takes a workflow execution as argument
        # Returns a string if the result is single, or a list if it's a list
        def get_json_value(execution_data, input_data):
            parsersplit = input_data.split(".")
            actionname_lower = parsersplit[0][1:].lower()

            #Actionname: Start_node

            # 1. Find the action
            baseresult = ""

            appendresult = "" 
            if (actionname_lower.startswith("exec ") or actionname_lower.startswith("webhook ") or actionname_lower.startswith("schedule ") or actionname_lower.startswith("userinput ") or actionname_lower.startswith("email_trigger ") or actionname_lower.startswith("trigger ")) and len(parsersplit) == 1:
                record = False
                for char in actionname_lower:
                    if char == " ":
                        record = True

                    if record:
                        appendresult += char

                actionname_lower = "exec"
            elif actionname_lower.startswith("shuffle_cache ") or actionname_lower.startswith("shuffle_db "): 
                actionname_lower = "shuffle_cache"

            actionname_lower = actionname_lower.replace(" ", "_", -1)

            try: 
                if actionname_lower == "exec" or actionname_lower == "webhook" or actionname_lower == "schedule" or actionname_lower == "userinput" or actionname_lower == "email_trigger" or actionname_lower == "trigger": 
                    baseresult = execution_data["execution_argument"]
                elif actionname_lower == "shuffle_cache":
                    if len(parsersplit) > 1:
                        actual_key = parsersplit[1]
                        cachedata = self.get_cache(actual_key)
                        parsersplit.pop(1)
                        try:
                            baseresult = json.dumps(cachedata)
                        except json.decoder.JSONDecodeError as e:
                            pass


                else:
                    if execution_data["results"] != None:
                        for result in execution_data["results"]:
                            resultlabel = result["action"]["label"].replace(" ", "_", -1).lower()
                            if resultlabel.lower() == actionname_lower:
                                baseresult = result["result"]
                                break
                    else:
                        baseresult = "$" + parsersplit[0][1:] 
                    
                    if len(baseresult) == 0:
                        try:
                            for variable in execution_data["workflow"]["workflow_variables"]:
                                variablename = variable["name"].replace(" ", "_", -1).lower()
        
                                if variablename.lower() == actionname_lower:
                                    baseresult = variable["value"]
                                    break

                        except KeyError as e:
                            pass
                        except TypeError as e:
                            pass
        
                    if len(baseresult) == 0:
                        try:
                            for variable in execution_data["execution_variables"]:
                                variablename = variable["name"].replace(" ", "_", -1).lower()
                                if variablename.lower() == actionname_lower:
                                    baseresult = variable["value"]
                                    break
                        except KeyError as e:
                            pass
                        except TypeError as e:
                            pass
        
            except KeyError as error:
                pass
        
            # 2. Find the JSON data
            # Returns if there isn't any JSON in the base ($nodename)
            if len(baseresult) == 0:
                return ""+appendresult, False
        
            # Returns if the result is JUST something like $nodename, not $nodename.value
            if len(parsersplit) == 1:
                returndata = str(baseresult)+str(appendresult)
                return returndata, False
        
            baseresult = baseresult.replace(" True,", " true,")
            baseresult = baseresult.replace(" False", " false,")

            # Tries to actually read it as JSON with some stupid formatting
            basejson = {}
            try:
                basejson = json.loads(baseresult)
            except json.decoder.JSONDecodeError as e:
                try:
                    baseresult = baseresult.replace("\'", "\"")
                    basejson = json.loads(baseresult)
                except json.decoder.JSONDecodeError as e:
                    return str(baseresult)+str(appendresult), False

            # Finds the ACTUAL value which is in the $nodename.value.test - focusing on value.test
            data, is_loop = recurse_json(basejson, parsersplit[1:])
            parseditem = data

            if isinstance(parseditem, dict) or isinstance(parseditem, list):
                try:
                    parseditem = json.dumps(parseditem)
                except json.decoder.JSONDecodeError as e:
                    pass

            if is_loop:
                if parsersplit[-1] == "#":
                    parseditem = "${SHUFFLE_NO_SPLITTER%s}$" % json.dumps(data)
                else:
                    # Return value: ${id[12345, 45678]}$
                    parseditem = "${%s%s}$" % (parsersplit[-1], json.dumps(data))


            returndata = str(parseditem)+str(appendresult)

            # New in 0.8.97: Don't return items without lists
            #return returndata, is_loop

            # 0.9.70:
            # The {} and [] checks are required because e.g. 7e7 is valid JSON for some reason...
            # This breaks EVERYTHING
            try:
                if (returndata.endswith("}") and returndata.endswith("}")) or (returndata.startswith("[") and returndata.endswith("]")):
                    return json.dumps(json.loads(returndata)), is_loop
                else:
                    return returndata, is_loop
            except json.decoder.JSONDecodeError as e:
                return returndata, is_loop



        # Sending self as it's not a normal function
        def parse_liquid(template, self):
            
            errors = False
            error_msg = ""
            try:
                if len(template) > 10000000:
                    self.logger.info("[DEBUG] Skipping liquid - size too big (%d)" % len(template))
                    return template

                if "${" in template and "}$" in template:
                    #self.logger.info("[DEBUG] Shuffle loop shouldn't run in liquid. Data length: %d" % len(template))
                    return template


                # New pattern fixer to help with bad liquid formats
                try:
                    newoutput = self.patternfix_string(template, 
                        {
                            "{{|": '{{ "" |',
                        },
                        {
                            r'\{\{\s*\$[^|}]+\s*\|': '{{ "" |',
                        }
                        , 
                        inputtype="liquid"
                    )

                    template = newoutput
                except Exception as e:
                    print("[ERROR] Failed liquid parsing fix: %s" % e)

                all_globals = globals()
                all_globals["self"] = self
                run = Liquid(template, mode="wild", from_file=False, filters=shuffle_filters.filters, globals=all_globals)

                # Add locals that are missing to globals
                ret = run.render()
                return ret
            except jinja2.exceptions.TemplateNotFound as e:
                self.logger.info(f"[ERROR] Liquid Template error: {e}")
                error = True
                error_msg = e

                self.action["parameters"].append({
                    "name": "liquid_template_error",
                    "value": f"There was a Liquid input error (1). Details: {e}",
                })

                self.action_result["action"] = self.action
            except SyntaxError as e:
                self.logger.info(f"[ERROR] Liquid Syntax error: {e}")
                error = True
                error_msg = e

                self.action["parameters"].append({
                    "name": "liquid_python_syntax_error",
                    "value": f"There was a syntax error in your Liquid input (2). Details: {e}",
                })

                self.action_result["action"] = self.action
            except IndentationError as e:
                self.logger.info(f"[ERROR] Liquid IndentationError: {e}")
                error = True
                error_msg = e

                self.action["parameters"].append({
                    "name": "liquid_indentiation_error",
                    "value": f"There was an indentation error in your Liquid input (2). Details: {e}",
                })

                self.action_result["action"] = self.action
            except jinja2.exceptions.TemplateSyntaxError as e:
                self.logger.info(f"[ERROR] Liquid Syntax error: {e}")
                error = True
                error_msg = e

                self.action["parameters"].append({
                    "name": "liquid_syntax_error",
                    "value": f"There was a syntax error in your Liquid input (2). Details: {e}",
                })

                self.action_result["action"] = self.action
            except json.decoder.JSONDecodeError as e:
                self.logger.info(f"[ERROR] Liquid JSON Syntax error: {e}")
                
                replace = False
                skip_next = False
                newlines = []
                thisline = []
                for line in template.split("\n"):
                    if "\"\"\"" in line or "\'\'\'" in line:
                        if replace:
                            skip_next = True
                        else:
                            replace = not replace 

                    if replace == True:
                        thisline.append(line)
                        if skip_next == True:
                            if len(thisline) > 0:
                                newlines.append(" ".join(thisline))
                                thisline = []

                            replace = False
                    else:
                        newlines.append(line)

                new_template = "\n".join(newlines)
                if new_template != template:
                    #check_template(new_template)
                    return parse_liquid(new_template, self)
                else:
                    error = True
                    error_msg = e

                    self.action["parameters"].append({
                        "name": "liquid_json_error",
                        "value": f"There was a syntax error in your input JSON(2). This is typically an issue with escaping newlines. Details: {e}",
                    })

                    self.action_result["action"] = self.action
            except TypeError as e:
                try:
                    if "string as left operand" in f"{e}":
                        split_left = template.split("|")
                        if len(split_left) < 2:
                            return template

                        splititem = split_left[0]
                        additem = "{{"
                        if "{{" in splititem:
                            splititem = splititem.replace("{{", "", -1)

                        if "{%" in splititem:
                            splititem = splititem.replace("{%", "", -1)
                            additem = "{%"

                        splititem = "%s \"%s\"" % (additem, splititem.strip())
                        parsed_template = template.replace(split_left[0], splititem)
                        run = Liquid(parsed_template, mode="wild", from_file=False)
                        return run.render(**globals())

                except Exception as e:
                    self.action["parameters"].append({
                        "name": "liquid_general_error",
                        "value": f"There was general error Liquid input (2). Details: {e}",
                    })

                    self.action_result["action"] = self.action
                    #return template

                self.logger.info(f"[ERROR] Liquid TypeError error: {e}")
                error = True
                error_msg = e

            except Exception as e:
                self.logger.info(f"[ERROR] General exception for liquid: {e}")
                error = True
                error_msg = e

                self.action["parameters"].append({
                    "name": "liquid_general_exception",
                    "value": f"There was general exception Liquid input (2). Details: {e}",
                })

                self.action_result["action"] = self.action

            if "fmt" in error_msg and "liquid_date" in error_msg:
                return template

            self.logger.info("Done in liquid")
            if error == True:
                self.action_result["status"] = "FAILURE" 
                data = {
                    "success": False,
                    "reason": f"Failed to parse LiquidPy: {error_msg}",
                    "input": template,
                }

                try:
                    self.action_result["result"] = json.dumps(data)
                except Exception as e:
                    self.action_result["result"] = f"Failed to parse LiquidPy: {error_msg}"

                self.action_result["completed_at"] = int(time.time_ns())
                self.send_result(self.action_result, headers, stream_path)

                self.logger.info(f"[ERROR] Sent FAILURE response to backend due to : {e}")
        
                if runtime == "run":
                    return template
                else:
                    os.exit()

            return template

        # Suboptimal cleanup script for BOdy parsing of OpenAPI
        # Should have a regex which looks for the value, then goes out and cleans up the key
        def recurse_cleanup_script(data):
            deletekeys = []
            newvalue = data
            try:
                if not isinstance(data, dict):
                    newvalue = json.loads(data)
                else:
                    newvalue = data
        
                for key, value in newvalue.items():
                    if isinstance(value, str) and len(value) == 0:
                        deletekeys.append(key)
                        continue
                            
                    if isinstance(value, list):
                        try:
                            value = json.dumps(value)
                        except:
                            pass
        
                    if value == "${%s}" % key:
                        deletekeys.append(key)
                        continue
                    elif "${" in value and "}" in value:
                        deletekeys.append(key)
                        continue
        
                    if isinstance(value, dict):
                        newvalue[key] = recurse_cleanup_script(value)
        
            except json.decoder.JSONDecodeError as e:
                # Since here the data isn't at all JSON compatible..?
                # Seems to happen with newlines in variables being parsed in as strings?
                pass
            except Exception as e:
                pass
                
            try:
                for deletekey in deletekeys:
                    try:
                        del newvalue[deletekey]
                    except:
                        pass
            except Exception as e:
                return data
        
            try:
                for key, value in newvalue.items():
                    if isinstance(value, bool):
                        continue
                    elif isinstance(value, dict) and not bool(value):
                        continue
        
                    try:
                        value = json.loads(value)
                        newvalue[key] = value
                    except json.decoder.JSONDecodeError as e:
                        continue
                    except Exception as e:
                        continue
        
                try:
                    data = json.dumps(newvalue)
                except json.decoder.JSONDecodeError as e:
                    data = newvalue
        
            except json.decoder.JSONDecodeError as e:
                pass
            except Exception as e:
                pass
        
            return data 

        # Makes JSON string values into valid strings in JSON
        # Mainly by removing newlines and such
        def fix_json_string_value(value):
            try:
                value = value.replace("\r\n", "\\r\\n")
                value = value.replace("\n", "\\n")
                value = value.replace("\r", "\\r")

                # Fix quotes in the string
                value = value.replace("\\\"", "\"")
                value = value.replace("\"", "\\\"")

                value = value.replace("\\\'", "\'")
                value = value.replace("\'", "\\\'")
            except Exception as e:
                pass

            return value



        # Parses parameters sent to it and returns whether it did it successfully with the values found
        def parse_params(action, fullexecution, parameter, self):
            # Skip if it starts with $?
            jsonparsevalue = "$."
            is_loop = False

            # Matches with space in the first part, but not in subsequent parts.
            # JSON / yaml etc shouldn't have spaces in their fields anyway.
            #match = ".*?([$]{1}([a-zA-Z0-9 _-]+\.?){1}([a-zA-Z0-9#_-]+\.?){0,})[$/, ]?"
            #match = ".*?([$]{1}([a-zA-Z0-9 _-]+\.?){1}([a-zA-Z0-9#_-]+\.?){0,})"

            #match = ".*?([$]{1}([a-zA-Z0-9_-]+\.?){1}([a-zA-Z0-9#_-]+\.?){0,})" # Removed space - no longer ok. Force underscore.
            #match = "([$]{1}([a-zA-Z0-9_-]+\.?){1}([a-zA-Z0-9#_-]+\.?){0,})" # Removed .*? to make it work with large amounts of data
            match = "([$]{1}([a-zA-Z0-9_@-]+\.?){1}([a-zA-Z0-9#_@-]+\.?){0,})" # Added @ to the regex

            # Extra replacements for certain scenarios
            escaped_dollar = "\\$"
            escape_replacement = "\\%\\%\\%\\%\\%"
            end_variable = "^_^"

            #self.logger.info("Input value: %s" % parameter["value"])
            try:
                parameter["value"] = parameter["value"].replace(escaped_dollar, escape_replacement, -1)
            except:
                self.logger.info("Error in initial replacement of escaped dollar!")

            paramname = ""
            try:
                paramname = parameter["name"]
            except:
                pass

            # Basic fix in case variant isn't set
            # Variant is ALWAYS STATIC_VALUE from mid 2021~ 
            try:
                parameter["variant"] = parameter["variant"]
            except:
                parameter["variant"] = "STATIC_VALUE"

            # Regex to find all the things
            # Should just go in here if data is ... not so big
            #if parameter["variant"] == "STATIC_VALUE" and len(parameter["value"]) < 1000000:
            #if parameter["variant"] == "STATIC_VALUE" and len(parameter["value"]) < 5000000:
            if parameter["variant"] == "STATIC_VALUE":
                data = parameter["value"]
                actualitem = re.findall(match, data, re.MULTILINE)
                #self.logger.debug(f"\n\nHandle static data with JSON: {data}\n\n")
                #self.logger.info("STATIC PARSED: %s" % actualitem)
                #self.logger.info("[INFO] Done with regex matching")
                if len(actualitem) > 0:
                    for replace in actualitem:
                        try:
                            to_be_replaced = replace[0]
                        except IndexError:
                            continue

                        # Handles for loops etc. 
                        # FIXME: Should it dump to string here? Doesn't that defeat the purpose?
                        # Trying without string dumping.
                        #self.logger.info("TO BE REPLACED: %s" % to_be_replaced)
                        value, is_loop = get_json_value(fullexecution, to_be_replaced) 

                        #self.logger.info(f"\n\nType of value: {type(value)}")
                        if isinstance(value, str):
                            # Could we take it here?
                            #self.logger.info(f"[DEBUG] Got value %s for parameter {paramname}" % value)
                            # Should check if there is are quotes infront of and after the to_be_replaced
                            # If there are, then we need to sanitize the value
                            # 1. Look for the to_be_replaced in the data
                            # 2. Check if there is a quote infront of it and also if there are {} in the data to validate JSON
                            # 3. If there are, sanitize!
                            #if data.find(f'"{to_be_replaced}"') != -1 and data.find("{") != -1 and data.find("}") != -1:
                            #    returnvalue = fix_json_string_value(value)
                            #    value = returnvalue

                            parameter["value"] = parameter["value"].replace(to_be_replaced, value, 1)
                        elif isinstance(value, dict) or isinstance(value, list):
                            # Changed from JSON dump to str() 28.05.2021
                            # This makes it so the parameters gets lists and dicts straight up
                            parameter["value"] = parameter["value"].replace(to_be_replaced, json.dumps(value), 1)

                            #try:
                            #    parameter["value"] = parameter["value"].replace(to_be_replaced, json.dumps(value))
                            #except:
                            #    parameter["value"] = parameter["value"].replace(to_be_replaced, str(value))
                            #    self.logger.info("Failed parsing value as string?")
                        else:
                            self.logger.error("[ERROR] Unknown type %s" % type(value))
                            try:
                                parameter["value"] = parameter["value"].replace(to_be_replaced, json.dumps(value), 1)
                            except json.decoder.JSONDecodeError as e:
                                parameter["value"] = parameter["value"].replace(to_be_replaced, value, 1)

            else:
                #self.logger.info(f"[ERROR] Not running static variant regex parsing (slow) on value with length {len(parameter['value'])}. Max is 5Mb~.")
                pass

            if parameter["variant"] == "WORKFLOW_VARIABLE":
                self.logger.info("[DEBUG] Handling workflow variable")
                found = False
                try:
                    for item in fullexecution["workflow"]["workflow_variables"]:
                        if parameter["action_field"] == item["name"]:
                            found = True
                            parameter["value"] = item["value"]
                            break
                except KeyError as e:
                    self.logger.info("KeyError WF variable 1: %s" % e)
                    pass
                except TypeError as e:
                    self.logger.info("TypeError WF variables 1: %s" % e)
                    pass

                if not found:
                    try:
                        for item in fullexecution["execution_variables"]:
                            if parameter["action_field"] == item["name"]:
                                parameter["value"] = item["value"]
                                break
                    except KeyError as e:
                        self.logger.info("KeyError WF variable 2: %s" % e)
                        pass
                    except TypeError as e:
                        self.logger.info("TypeError WF variables 2: %s" % e)
                        pass

            elif parameter["variant"] == "ACTION_RESULT":
                # FIXME - calculate value based on action_field and $if prominent
                # FIND THE RIGHT LABEL
                # GET THE LABEL'S RESULT 
                
                tmpvalue = ""
                self.logger.info("ACTION FIELD: %s" % parameter["action_field"])

                fullname = "$"
                if parameter["action_field"] == "Execution Argument":
                    tmpvalue = fullexecution["execution_argument"]
                    fullname += "exec"
                else:
                    fullname += parameter["action_field"]

                self.logger.info("PRE Fullname: %s" % fullname)

                if parameter["value"].startswith(jsonparsevalue):
                    fullname += parameter["value"][1:]
                #else:
                #    fullname = "$%s" % parameter["action_field"]

                self.logger.info("Fullname: %s" % fullname)
                actualitem = re.findall(match, fullname, re.MULTILINE)
                self.logger.info("ACTION PARSED: %s" % actualitem)
                if len(actualitem) > 0:
                    for replace in actualitem:
                        try:
                            to_be_replaced = replace[0]
                        except IndexError:
                            self.logger.info("Nothing to replace?: " % e)
                            continue
                        
                        # This will never be a loop aka multi argument
                        parameter["value"] = to_be_replaced 

                        value, is_loop = get_json_value(fullexecution, to_be_replaced)
                        self.logger.info("Loop: %s" % is_loop)
                        if isinstance(value, str):
                            parameter["value"] = parameter["value"].replace(to_be_replaced, value)
                        elif isinstance(value, dict):
                            parameter["value"] = parameter["value"].replace(to_be_replaced, json.dumps(value))
                        else:
                            self.logger.info("Unknown type %s" % type(value))
                            try:
                                parameter["value"] = parameter["value"].replace(to_be_replaced, json.dumps(value))
                            except json.decoder.JSONDecodeError as e:
                                parameter["value"] = parameter["value"].replace(to_be_replaced, value)

            #self.logger.info("PRE Replaced data: %s" % parameter["value"])

            try:
                parameter["value"] = parameter["value"].replace(end_variable, "", -1)
                parameter["value"] = parameter["value"].replace(escape_replacement, "$", -1)
            except:
                self.logger.info(f"[ERROR] Problem in datareplacement: {e}")

            # Just here in case it breaks 
            # Implemented 02.08.2021
            #self.logger.info("Pre liquid: %s" % parameter["value"])
            try:
                parameter["value"] = parse_liquid(parameter["value"], self)
            except:
                pass

            return "", parameter["value"], is_loop

        def run_validation(sourcevalue, check, destinationvalue):
            #self.logger.info("[DEBUG] Checking %s '%s' %s" % (sourcevalue, check, destinationvalue))

            if check == "=" or check.lower() == "equals":
                if str(sourcevalue).lower() == str(destinationvalue).lower():
                    return True
            elif check == "!=" or check.lower() == "does not equal":
                if str(sourcevalue).lower() != str(destinationvalue).lower():
                    return True
            elif check.lower() == "startswith":
                if str(sourcevalue).lower().startswith(str(destinationvalue).lower()):
                    return True
            elif check.lower() == "endswith":
                if str(sourcevalue).lower().endswith(str(destinationvalue).lower()):
                    return True
            elif check.lower() == "contains":
                if destinationvalue.lower() in sourcevalue.lower():
                    return True

            elif check.lower() == "is empty" or check.lower() == "is_empty":
                try:
                    if len(json.loads(sourcevalue)) == 0:
                        return True
                except Exception as e:
                    self.logger.info(f"[WARNING] Failed to check if empty as list: {e}")

                if len(str(sourcevalue)) == 0:
                    return True

            elif check.lower() == "contains_any_of":
                newvalue = [destinationvalue.lower()]
                if "," in destinationvalue:
                    newvalue = destinationvalue.split(",")
                elif ", " in destinationvalue:
                    newvalue = destinationvalue.split(", ")

                for item in newvalue:
                    if not item:
                        continue

                    if item.strip() in sourcevalue:
                        return True
                    
            elif check.lower() == "larger than" or check.lower() == "bigger than":
                try:
                    if str(sourcevalue).isdigit() and str(destinationvalue).isdigit():
                        if int(sourcevalue) > int(destinationvalue):
                            return True

                except AttributeError as e:
                    self.logger.info("[WARNING] Condition larger than failed with values %s and %s: %s" % (sourcevalue, destinationvalue, e))

                try:
                    destinationvalue = len(json.loads(destinationvalue))
                except Exception as e:
                    self.logger.info(f"[WARNING] Failed to convert destination to list: {e}")
                try:
                    # Check if it's a list in autocast and if so, check the length
                    if len(json.loads(sourcevalue)) > int(destinationvalue):
                        return True
                except Exception as e:
                    self.logger.info(f"[WARNING] Failed to check if larger than as list: {e}")


            elif check.lower() == "smaller than" or check.lower() == "less than":
                self.logger.info("In smaller than check: %s %s" % (sourcevalue, destinationvalue))

                try:
                    if str(sourcevalue).isdigit() and str(destinationvalue).isdigit():
                        if int(sourcevalue) < int(destinationvalue):
                            return True

                except AttributeError as e:
                    pass

                try:
                    destinationvalue = len(json.loads(destinationvalue))
                except Exception as e:
                    self.logger.info(f"[WARNING] Failed to convert destination to list: {e}")

                try:
                    # Check if it's a list in autocast and if so, check the length
                    if len(json.loads(sourcevalue)) < int(destinationvalue):
                        return True
                except Exception as e:
                    self.logger.info(f"[WARNING] Failed to check if smaller than as list: {e}")

            elif check.lower() == "re" or check.lower() == "matches regex":
                try:
                    found = re.search(str(destinationvalue), str(sourcevalue))
                except re.error as e:
                    return False
                except Exception as e:
                    return False

                if found == None:
                    return False

                return True
            else:
                self.logger.error("[DEBUG] Condition: can't handle %s yet. Setting to true" % check)

            return False

        def check_branch_conditions(action, fullexecution, self):
            # relevantbranches = workflow.branches where destination = action
            try:
                if fullexecution["workflow"]["branches"] == None or len(fullexecution["workflow"]["branches"]) == 0:
                    return True, ""
            except KeyError:
                return True, ""

            # Startnode should always run - no need to check incoming
            # Removed November 2023 due to people wanting startnode to also check
            # This is to make it possible ot 
            try:
                if action["id"] == fullexecution["start"]:
                    return True, ""

            except Exception as error:
                self.logger.info(f"[WARNING] Failed checking startnode: {error}")
                #return True, ""
                #return True, ""

            available_checks = [
                "=",
                "equals",
                "!=",
                "does not equal",
                ">",
                "larger than",
                "<",
                "less than",
                ">=",
                "<=",
                "startswith",
                "endswith",
                "contains",
                "contains_any_of",
                "re",
                "matches regex",
                "is empty",
                "is_empty",
            ]

            relevantbranches = []
            correct_branches = 0
            matching_branches = 0
            for branch in fullexecution["workflow"]["branches"]:
                if branch["destination_id"] != action["id"]:
                    continue

                matching_branches += 1

                # Find if previous is skipped or failed. Skipped != correct branch
                try:
                    should_skip = False
                    for res in fullexecution["results"]:
                        if res["action"]["id"] == branch["source_id"]:
                            if res["status"] == "FAILURE" or res["status"] == "SKIPPED":
                                should_skip = True 

                            break

                    if should_skip:
                        continue
                except Exception as e:
                    self.logger.info("[WARNING] Failed handling check of if parent is skipped") 


                # Remove anything without a condition
                try:
                    if (branch["conditions"]) == 0 or branch["conditions"] == None:
                        correct_branches += 1
                        continue
                except KeyError:
                    correct_branches += 1
                    continue

                successful_conditions = []
                failed_conditions = []
                successful_conditions = 0
                total_conditions = len(branch["conditions"])
                for condition in branch["conditions"]:
                    # Parse all values first here
                    sourcevalue = condition["source"]["value"]
                    check, sourcevalue, is_loop = parse_params(action, fullexecution, condition["source"], self)
                    if check:
                        continue

                    sourcevalue = parse_wrapper_start(sourcevalue, self)
                    destinationvalue = condition["destination"]["value"]

                    check, destinationvalue, is_loop = parse_params(action, fullexecution, condition["destination"], self)
                    if check:
                        continue

                    destinationvalue = parse_wrapper_start(destinationvalue, self)

                    if not condition["condition"]["value"] in available_checks:
                        self.logger.error("[ERROR] Skipping '%s' -> %s -> '%s' because %s is invalid." % (sourcevalue, condition["condition"]["value"], destinationvalue, condition["condition"]["value"]))
                        continue

                    # Configuration = negated because of WorkflowAppActionParam..
                    validation = run_validation(sourcevalue, condition["condition"]["value"], destinationvalue)
                    try:
                        if condition["condition"]["configuration"]:
                            validation = not validation
                    except KeyError:
                        pass

                    if validation == True:
                        successful_conditions += 1

                if total_conditions == successful_conditions:
                    correct_branches += 1
    
            if matching_branches == 0:
                return True, ""

            if matching_branches > 0 and correct_branches > 0:
                return True, ""

            #self.logger.info("[DEBUG] Correct branches vs matching branches: %d vs %d" % (correct_branches, matching_branches))
            return False, {"success": False, "reason": "Minimum of one branch's conditions must be correct to continue. Total: %d of %d" % (correct_branches, matching_branches)}


        #
        #
        #
        #
        # CONT
        # CONT
        # CONT
        # CONT
        # CONT
        # CONT
        # CONT
        # CONT
        # CONT
        # CONT
        # CONT
        # CONT
        # CONT
        #
        #
        #
        #

        # THE START IS ACTUALLY RIGHT HERE :O
        # Checks whether conditions are met, otherwise set 
        branchcheck, tmpresult = check_branch_conditions(action, fullexecution, self)
        if isinstance(tmpresult, object) or isinstance(tmpresult, list) or isinstance(tmpresult, dict):
            #self.logger.info("[DEBUG] Fixing branch return as object -> string")
            try:
                #tmpresult = tmpresult.replace("'", "\"")
                tmpresult = json.dumps(tmpresult) 
            except json.decoder.JSONDecodeError as e:
                pass


        # IF branches fail: Exit!
        if not branchcheck:
            self.action_result["result"] = tmpresult
            self.action_result["status"] = "SKIPPED"
            self.action_result["completed_at"] = int(time.time_ns())

            self.send_result(self.action_result, headers, stream_path)
            return

        # Replace name cus there might be issues
        # Not doing lower() as there might be user-made functions
        actionname = action["name"]
        if " " in actionname:
            actionname.replace(" ", "_", -1) 

        #if action.generated:
        #    actionname = actionname.lower()

        # Runs the actual functions
        try:
            func = getattr(self, actionname, None)
            if func == None:
                self.logger.debug(f"[DEBUG] Failed executing {actionname} because func is None (no function specified).")
                self.action_result["status"] = "FAILURE" 
                self.action_result["result"] = json.dumps({
                    "success": False,
                    "reason": f"Function {actionname} doesn't exist, or the App is out of date.",
                    "details": "If this persists, please delete the Docker image locally, then restart your Orborus instance before trying again. This will force-download the latest version. Contact support@shuffler.io with this data if the issue persists.",
                })
            elif callable(func):
                try:
                    if len(action["parameters"]) < 1:
                        #result = await func()
                        result = func()
                    else:
                        # Potentially parse JSON here
                        # FIXME - add potential authentication as first parameter(s) here
                        # params[parameter["name"]] = parameter["value"]
                        #self.logger.info(fullexecution["authentication"]
                        # What variables are necessary here tho hmm

                        params = {}

                        # Fixes OpenAPI body parameters for later.
                        newparams = []
                        counter = -1
                        bodyindex = -1
                        for parameter in action["parameters"]:
                            counter += 1

                            # Hack for key:value in options using ||
                            try:
                                if parameter["options"] != None and len(parameter["options"]) > 0:
                                    #self.logger.info(f'OPTIONS: {parameter["options"]}')
                                    #self.logger.info(f'OPTIONS VAL: {parameter}')
                                    if "||" in parameter["value"]:
                                        splitvalue = parameter["value"].split("||")
                                        if len(splitvalue) > 1:
                                            #self.logger.info(f'[INFO] Parsed split || options of actions["parameters"]["name"]')
                                            action["parameters"][counter]["value"] = splitvalue[1]

                            except (IndexError, KeyError, TypeError) as e:
                                self.logger.info("[WARNING] Options err: {e}")

                            # This part is purely for OpenAPI accessibility. 
                            # It replaces the data back into the main item
                            # Earlier, we handled each of the items and did later string replacement, 
                            # but this has changed to do lists within items and such
                            if parameter["name"] == "body": 
                                bodyindex = counter

                                try:
                                    values = parameter["value_replace"]
                                    if values != None:
                                        added = 0
                                        for val in values:
                                            replace_value = val["value"]
                                            replace_key = val["key"]

                                            if (val["value"].startswith("{") and val["value"].endswith("}")) or (val["value"].startswith("[") and val["value"].endswith("]")):
                                                self.logger.info(f"""Trying to parse as JSON: {val["value"]}""")
                                                try:
                                                    newval = val["value"]

                                                    # If it gets here, remove the "" infront and behind the key as well 
                                                    # since this is preventing the JSON from being loaded
                                                    tmpvalue = json.loads(newval)
                                                    replace_key = f"\"{replace_key}\""
                                                except json.decoder.JSONDecodeError as e:
                                                    self.logger.info("[WARNING] Failed JSON replacement for OpenAPI %s", val["key"])

                                            elif val["value"].lower() == "true" or val["value"].lower() == "false":
                                                replace_key = f"\"{replace_key}\""
                                            else:
                                                if "\"" in replace_value and not "\\\"" in replace_value:
                                                    replace_value = replace_value.replace("\"", "\\\"", -1)

                                            action["parameters"][counter]["value"] = action["parameters"][counter]["value"].replace(replace_key, replace_value, 1)

                                            self.logger.info(f'[INFO] Added param {val["key"]} for body (using OpenAPI)')
                                            added += 1

                                        #action["parameters"]["body"]

                                        self.logger.info("ADDED %d parameters for body" % added)
                                except KeyError as e:
                                    self.logger.info("KeyError body OpenAPI: %s" % e)
                                    pass

                                 
                                action["parameters"][counter]["value"] = recurse_cleanup_script(action["parameters"][counter]["value"])

                        #self.logger.info(action["parameters"])

                        # This seems redundant now 
                        for parameter in newparams:
                            action["parameters"].append(parameter)

                        self.action = action

                        # Setting due to them being overwritten, but still later useful
                        try:
                            self.original_action = json.loads(json.dumps(action))
                        except Exception as e:
                            pass

                        # calltimes is used to handle forloops in the app itself.
                        # 2 kinds of loop - one in gui with one app each, and one like this,
                        # which is super fast, but has a bad overview (potentially good tho)
                        calltimes = 1
                        result = ""

                        all_executions = []

                        # Multi_parameter has the data for each. variable
                        minlength = 0
                        multi_parameters = json.loads(json.dumps(params))
                        multiexecution = False
                        multi_execution_lists = []
                        remove_params = []
                        for parameter in action["parameters"]:
                            check, value, is_loop = parse_params(action, fullexecution, parameter, self)
                            if check:
                                raise Exception(json.dumps({
                                    "success": False,
                                    "exception": f"Value Error: {check}",
                                    "reason": "Parameter {parameter} has an issue",
                                }))

                            #if parameter["name"] == "body": 
                            #    #self.logger.info(f"[INFO] Should debug field with liquid and other checks as it's BODY: {value}")

                            # Custom format for ${name[0,1,2,...]}$
                            #submatch = "([${]{2}([0-9a-zA-Z_-]+)(\[.*\])[}$]{2})"
                            #self.logger.info(f"Returnedvalue: {value}")
                            # OLD: Used until 13.03.2021: submatch = "([${]{2}#?([0-9a-zA-Z_-]+)#?(\[.*\])[}$]{2})"
                            # \${[0-9a-zA-Z_-]+#?(\[.*?]}\$)
                            submatch = "([${]{2}#?([0-9a-zA-Z_-]+)#?(\[.*?]}\$))"
                            actualitem = re.findall(submatch, value, re.MULTILINE)
                            try:
                                if action["skip_multicheck"]:
                                    self.logger.info("Skipping multicheck")
                                    actualitem = []
                            except KeyError:
                                pass

                            actionname = action["name"]
                                
                            # Loops in general goes in here to be parsed out as one->multi
                            if len(actualitem) > 0:
                                self.logger.info(f"[INFO] Found {len(actualitem)} items in {parameter['name']}. MULTI EXEC.")
                                multiexecution = True

                                handled = False

                                # Has a loop without a variable used inside
                                
                                # This is here to handle for loops within variables.. kindof
                                # 1. Find the length of the longest array
                                # 2. Build an array with the base values based on parameter["value"] 
                                # 3. Get the n'th value of the generated list from values
                                # 4. Execute all n answers 
                                replacements = {}
                                curminlength = 0
                                for replace in actualitem:
                                    try:
                                        to_be_replaced = replace[0]
                                        actualitem = replace[2]
                                        if actualitem.endswith("}$"):
                                            actualitem = actualitem[:-2]

                                    except IndexError:
                                        self.logger.info("[WARNING] Indexerror")
                                        continue

                                    try:
                                        itemlist = json.loads(actualitem)
                                        if len(itemlist) > minlength:
                                            minlength = len(itemlist)

                                        if len(itemlist) > curminlength:
                                            curminlength = len(itemlist)
                                        
                                    except json.decoder.JSONDecodeError as e:
                                        self.logger.info("JSON Error (replace): %s in %s" % (e, actualitem))

                                    replacements[to_be_replaced] = actualitem


                                # Parses the data as string with length, split etc. before moving on. 
                                #self.logger.info("In second part of else: %s" % (len(itemlist)))
                                # This is a result array for JUST this value.. 
                                # What if there are more?
                                resultarray = []
                                for i in range(0, curminlength): 
                                    tmpitem = json.loads(json.dumps(parameter["value"]))
                                    for key, value in replacements.items():
                                        replacement = value
                                        try:
                                            replacement = json.dumps(json.loads(value)[i])
                                        except IndexError as e:
                                            self.logger.info(f"[ERROR] Failed handling value parsing with index: {e}")
                                            pass

                                        if replacement.startswith("\"") and replacement.endswith("\""):
                                            replacement = replacement[1:len(replacement)-1]

                                        #except json.decoder.JSONDecodeError as e:

                                        #self.logger.info("REPLACING %s with %s" % (key, replacement))
                                        #replacement = parse_wrapper_start(replacement)
                                        tmpitem = tmpitem.replace(key, replacement, -1)
                                        try:
                                            tmpitem = parse_liquid(tmpitem, self)
                                        except Exception as e:
                                            self.logger.info(f"[WARNING] Failed liquid parsing in loop (2): {e}")


                                    # This code handles files.
                                    isfile = False
                                    try:
                                        if parameter["schema"]["type"] == "file" and len(value) > 0:
                                            self.logger.info("(2) SHOULD HANDLE FILE IN MULTI. Get based on value %s" % parameter["value"]) 

                                            for tmp_file_split in json.loads(parameter["value"]):
                                                file_value = self.get_file(tmp_file_split)
                                                resultarray.append(file_value)


                                            isfile = True
                                    except KeyError as e:
                                        self.logger.info("(2) SCHEMA ERROR IN FILE HANDLING: %s" % e)
                                    except json.decoder.JSONDecodeError as e:
                                        self.logger.info("(2) JSON ERROR IN FILE HANDLING: %s" % e)

                                    if not isfile:
                                        #tmpitem = tmpitem.replace("\\\\", "\\", -1)
                                        resultarray.append(tmpitem)

                                # With this parameter ready, add it to... a greater list of parameters. Rofl
                                if len(resultarray) == 0:
                                    self.logger.info("[WARNING] Returning empty array because the array length to be looped is 0 (0)")
                                    self.action_result["status"] = "SUCCESS" 
                                    self.action_result["result"] = "[]"
                                    self.send_result(self.action_result, headers, stream_path)
                                    return

                                #self.logger.info("RESULTARRAY: %s" % resultarray)
                                if resultarray not in multi_execution_lists:
                                    multi_execution_lists.append(resultarray)

                                multi_parameters[parameter["name"]] = resultarray
                            else:
                                # Parses things like int(value)
                                #self.logger.info("[DEBUG] Normal parsing (not looping)")#with data %s" % value)
                                # This part has fucked over so many random JSON usages because of weird paranthesis parsing

                                value = parse_wrapper_start(value, self)

                                try:
                                    if str(value).startswith("b'") and str(value).endswith("'"):
                                        value = value[2:-1]
                                except Exception as e:
                                    pass

                                params[parameter["name"]] = value
                                multi_parameters[parameter["name"]] = value 

                                # This code handles files.
                                try:
                                    if parameter["schema"]["type"] == "file" and len(value) > 0:
                                        self.logger.info("\n SHOULD HANDLE FILE. Get based on value %s. <--- is this a valid ID?" % parameter["value"]) 
                                        file_value = self.get_file(value)
                                        self.logger.info("FILE VALUE: %s \n" % file_value)

                                        params[parameter["name"]] = file_value 
                                        multi_parameters[parameter["name"]] = file_value 
                                except KeyError as e:
                                    self.logger.info("SCHEMA ERROR IN FILE HANDLING: %s" % e)

                            
                        # Fix lists here
                        # FIXME: This doesn't really do anything anymore
                        #self.logger.info("[DEBUG] CHECKING multi execution list: %d!" % len(multi_execution_lists))
                        if len(multi_execution_lists) > 0:
                            filteredlist = []
                            for listitem in multi_execution_lists:
                                if listitem in filteredlist:
                                    continue

                                # FIXME: Subsub required?. Recursion! 
                                # Basically multiply what we have with the outer loop?
                                # 
                                #if isinstance(listitem, list):
                                #    for subitem in listitem:
                                #        filteredlist.append(subitem)
                                #else:
                                #    filteredlist.append(listitem)

                            #self.logger.info("New list length: %d" % len(filteredlist))
                            if len(filteredlist) > 1:
                                self.logger.info(f"Calculating new multi-loop length with {len(filteredlist)} lists")
                                tmplength = 1
                                for innerlist in filteredlist:
                                    tmplength = len(innerlist)*tmplength
                                    self.logger.info("List length: %d. %d*%d" % (tmplength, len(innerlist), tmplength))

                                minlength = tmplength

                                self.logger.info("New multi execution length: %d\n" % tmplength)

                        # Cleaning up extra list params
                        for subparam in remove_params:
                            #self.logger.info(f"DELETING {subparam}")
                            try:
                                del params[subparam]
                            except:
                                pass
                                #self.logger.info(f"Error with subparam deletion of {subparam} in {params}")
                            try:
                                del multi_parameters[subparam]
                            except:
                                #self.logger.info(f"Error with subparam deletion of {subparam} in {multi_parameters} (2)")
                                pass

                        #self.logger.info()
                        #self.logger.info(f"Param: {params}")
                        #self.logger.info(f"Multiparams: {multi_parameters}")
                        #self.logger.info()
                        
                        if not multiexecution:
                            self.logger.info("NOT MULTI EXEC")
                            # Runs a single iteration here
                            new_params = self.validate_unique_fields(params)
                            if isinstance(new_params, list) and len(new_params) == 1:
                                params = new_params[0]
                                #params = new_params
                            else:
                                #self.logger.info("[WARNING] SHOULD STOP EXECUTION BECAUSE FIELDS AREN'T UNIQUE")
                                self.action_result["status"] = "SKIPPED"
                                self.action_result["result"] = f"A non-unique value was found"  
                                self.action_result["completed_at"] = int(time.time_ns())
                                self.send_result(self.action_result, headers, stream_path)
                                return

                            #self.logger.info("[INFO] Running normal execution (not loop)\n\n") 

                            # Added literal evaluation of anything resembling a string
                            # The goal is to parse objects that e.g. use single quotes and the like
                            # FIXME: add this to Multi exec as well.
                            try:
                                for key, value in params.items():
                                    if "-" in key:
                                        try:
                                            newkey = key.replace("-", "_", -1).lower()
                                            params[newkey] = params[key]
                                        except Exception as e:
                                            self.logger.info("[DEBUG] Failed updating key with dash in it: %s" % e)

                                    try:
                                        if isinstance(value, str) and ((value.startswith("{") and value.endswith("}")) or (value.startswith("[") and value.endswith("]"))):
                                            params[key] = json.loads(value)
                                    except Exception as e:
                                        try:
                                            if isinstance(value, str) and ((value.startswith("{") and value.endswith("}")) or (value.startswith("[") and value.endswith("]"))):
                                                params[key] = ast.literal_eval(value)
                                        except Exception as e:
                                            self.logger.info(f"[DEBUG] Failed parsing value with ast and json.loads - noncritical. Trying next: {e}")
                                            continue
                            except Exception as e:
                                self.logger.info("[DEBUG] Failed looping objects. Non critical: {e}")

                            # Uncomment below to get the param input
                            # self.logger.info(f"[DEBUG] PARAMS: {params}")

                            #newres = ""
                            iteration_count = 0
                            found_error = ""
                            while True:
                                iteration_count += 1
                                if iteration_count >= 10:
                                    newres = {
                                        "success": False,
                                        "reason": "Iteration count more than 10. This happens if the input to the action is wrong. Try remaking the action, and contact support@shuffler.io if this persists.", 
                                        "details": f"{found_error}",
                                    }
                                    break

                                try:
                                    #try:
                                    # Individual functions shouldn't take longer than this
                                    # This is an attempt to make timeouts occur less, incentivizing users to make use efficient API's
                                    # PS: Not implemented for lists - only single actions as of May 2023
                                    timeout = 30 

                                    # Check if current app is Shuffle Tools, then set to 55 due to certain actions being slow (ioc parser..) 
                                    # In general, this should be disabled for onprem 
                                    if self.action["app_name"].lower() == "shuffle tools":
                                        timeout = 55

                                    timeout_env = os.getenv("SHUFFLE_APP_SDK_TIMEOUT", timeout)
                                    try:
                                        timeout = int(timeout_env)
                                        #self.logger.info(f"[DEBUG] Timeout set to {timeout} seconds")  
                                    except Exception as e:
                                        self.logger.info(f"[ERROR] Failed parsing timeout to int: {e}")

                                    #timeout = 30 
                                    self.logger.info("[DEBUG][%s] Running function '%s' with timeout %d" % (self.current_execution_id, action["name"], timeout))

                                    try:
                                        executor = concurrent.futures.ThreadPoolExecutor()
                                        future = executor.submit(func, **params)
                                        newres = future.result(timeout)

                                        if not future.done():
                                            # The future is still running, so we need to cancel it
                                            future.cancel()
                                            newres = json.dumps({
                                                "success": False,
                                                "exception": str(e),
                                                "reason": "Timeout error within %d seconds (1). This happens if we can't reach or use the API you're trying to use within the time limit. Configure SHUFFLE_APP_SDK_TIMEOUT=100 in Orborus to increase it to 100 seconds. Not changeable for cloud." % timeout,
                                            })

                                        else:
                                            # The future is done, so we can just get the result from newres :)
                                            #newres = future.result()
                                            pass

                                    except concurrent.futures.TimeoutError as e:
                                        newres = json.dumps({
                                            "success": False,
                                            "reason": "Timeout error (2) within %d seconds (2). This happens if we can't reach or use the API you're trying to use within the time limit. Configure SHUFFLE_APP_SDK_TIMEOUT=100 in Orborus to increase it to 100 seconds. Not changeable for cloud." % timeout,
                                        })

                                    break
                                except TypeError as e:
                                    newres = ""
                                    self.logger.info(f"[ERROR] Got function exec type error: {e}")
                                    try:
                                        e = json.loads(f"{e}")
                                    except:
                                        e = f"{e}"

                                    found_error = e 
                                    errorstring = f"{e}"

                                    if "the JSON object must be" in errorstring:
                                        self.logger.info("[ERROR] Something is wrong with the input for this function. Are lists and JSON data handled parsed properly (0)? the JSON object must be in...")

                                        newres = json.dumps({
                                            "success": False,
                                            "exception": f"{type(e).__name__} - {e}",
                                            "reason": "An exception occurred while running this function (1). See exception for more details and contact support if this persists (support@shuffler.io)",
                                        })
                                        break
                                    elif "got an unexpected keyword argument" in errorstring:
                                        fieldsplit = errorstring.split("'")
                                        if len(fieldsplit) > 1:
                                            field = fieldsplit[1]
                            
                                            try:
                                                del params[field]
                                                self.logger.info("[WARNING] Removed invalid field %s (2)" % field)
                                            except KeyError:
                                                break
                                    else:
                                        newres = json.dumps({
                                            "success": False,
                                            "exception": f"TypeError: {e}",
                                            "reason": "You may be running an old version of this action. Try remaking the node, then contact us at support@shuffler.io if it doesn't work with all these details.",
                                        })
                                        break
                                except Exception as e:
                                    self.logger.info(f"[ERROR] Something is wrong with the input for this function. Are lists and JSON data handled parsed properly (1)? err: {e}")

                                    #try:
                                    #    e = json.loads(f"{e}")
                                    #except:
                                    #    e = f"{e}"

                                    newres = json.dumps({
                                        "success": False,
                                        "exception": f"{type(e).__name__} - {e}",
                                        "reason": "An exception occurred while running this function (2). See exception for more details and contact support if this persists (support@shuffler.io)",
                                        
                                    })
                                    break

                            # Forcing async wait in case of old apps that use async (backwards compatibility)
                            try:
                                if asyncio.iscoroutine(newres):
                                    self.logger.info("[DEBUG] In coroutine (1)")
                                    async def parse_value(newres):
                                        value = await asyncio.gather(
                                            newres 
                                        )

                                        return value[0]

                                    newres = asyncio.run(parse_value(newres))
                                else:
                                    #self.logger.info("[DEBUG] Not in coroutine (1)")
                                    pass
                            except Exception as e:
                                self.logger.warning("[ERROR] Failed to parse coroutine value for old app: {e}")

                            #self.logger.info("\n\n\n[INFO] Returned from execution with type(s) %s" % type(newres))
                            #self.logger.info("\n[INFO] Returned from execution with %s of types %s" % (newres, type(newres)))#, newres)
                            if isinstance(newres, tuple):
                                #self.logger.info(f"[INFO] Handling return as tuple: {newres}")
                                # Handles files.
                                filedata = ""
                                file_ids = []
                                if isinstance(newres[1], list):
                                    self.logger.info("[INFO] HANDLING LIST FROM RET")
                                    file_ids = self.set_files(newres[1])
                                elif isinstance(newres[1], object):
                                    self.logger.info("[INFO] Handling JSON from ret")
                                    file_ids = self.set_files([newres[1]])
                                elif isinstance(newres[1], str):
                                    self.logger.info("[INFO] Handling STRING from ret")
                                    file_ids = self.set_files([newres[1]])
                                else:
                                    self.logger.info("[INFO] NO FILES TO HANDLE")

                                tmp_result = {
                                    "success": True,
                                    "result": newres[0], 
                                    "file_ids": file_ids
                                }
                                
                                result = json.dumps(tmp_result)
                            elif isinstance(newres, str):
                                #self.logger.info("[INFO] Handling return as string of length %d" % len(newres))
                                result += newres
                            elif isinstance(newres, dict) or isinstance(newres, list):
                                try:
                                    result += json.dumps(newres, indent=4)
                                except json.JSONDecodeError as e:
                                    self.logger.info("[WARNING] Failed decoding result: %s" % e)
                                    try:
                                        result += str(newres)
                                    except ValueError:
                                       result += "Failed autocasting. Can't handle %s type from function. Must be string" % type(newres)
                                        self.logger.info("[ERROR] Can't handle type %s value from function" % (type(newres)))
                                except Exception as e:
                                    self.logger.info("[ERROR] Failed to json dump. Returning as string.")
                                    result += str(newres)
                            else:
                                try:
                                    result += str(newres)
                                except ValueError:
                                    result += "Failed autocasting. Can't handle %s type from function. Must be string" % type(newres)
                                    self.logger.info("Can't handle type %s value from function" % (type(newres)))

                        else:
                            #self.logger.info("[INFO] APP_SDK DONE: Starting MULTI execution (length: %d) with values %s" % (minlength, multi_parameters))
                            # 1. Use number of executions based on the arrays being similar
                            # 2. Find the right value from the parsed multi_params

                            #self.logger.info("[INFO] Running WITH loop. MULTI: %s", multi_parameters)
                            self.logger.info("[INFO] Running WITH loop")
                            json_object = False
                            #results = await self.run_recursed_items(func, multi_parameters, {})
                            results = self.run_recursed_items(func, multi_parameters, {})
                            if isinstance(results, dict) or isinstance(results, list):
                                json_object = True

                            # Dump the result as a string of a list
                            #self.logger.info("RESULTS: %s" % results)
                            if isinstance(results, list) or isinstance(results, dict):

                                # This part is weird lol
                                if json_object:
                                    try:
                                        result = json.dumps(results)
                                    except json.JSONDecodeError as e:
                                        self.logger.info(f"Failed to decode: {e}")
                                        result = results
                                else:
                                    result = "["
                                    for item in results:
                                        try:
                                            json.loads(item)
                                            result += item
                                        except json.decoder.JSONDecodeError as e:
                                            # Common nested issue which puts " around everything
                                            self.logger.info("Decodingerror: %s" % e)
                                            try:
                                                tmpitem = item.replace("\\\"", "\"", -1)
                                                json.loads(tmpitem)
                                                result += tmpitem

                                            except:
                                                result += "\"%s\"" % item

                                        result += ", "

                                    result = result[:-2]
                                    result += "]"
                            else:
                                self.logger.info("Normal result - no list?")
                                result = results

                    self.action_result["status"] = "SUCCESS" 
                    self.action_result["result"] = str(result)
                    if self.action_result["result"] == "":
                        self.action_result["result"] = result

                    #self.logger.debug(f"[DEBUG] Executed {action['label']}-{action['id']}")#with result: {result}")
                    #self.logger.debug(f"Data: %s" % action_result)
                except TypeError as e:
                    self.logger.info("[ERROR] TypeError issue: %s" % e)
                    self.action_result["status"] = "FAILURE" 
                    self.action_result["result"] = json.dumps({
                        "success": False, 
                        "reason": f"Typeerror. Most likely due to a list that should've been a string. See details for more info.",
                        "details": f"{e}",
                    })
                    #self.action_result["result"] = "TypeError: %s" % str(e)
            else:
                self.logger.info("[DEBUG] Function %s doesn't exist?" % action["name"])
                self.logger.error(f"[ERROR] App {self.__class__.__name__}.{action['name']} is not callable")
                self.action_result["status"] = "FAILURE" 
                #self.action_result["result"] = "Function %s is not callable." % actionname

                self.action_result["result"] = json.dumps({
                    "success": False, 
                    "reason": f"Function %s doesn't exist." % actionname,
                })

        # https://ptb.discord.com/channels/747075026288902237/882017498550112286/882043773138382890
        except (requests.exceptions.RequestException, TimeoutError) as e:
            self.logger.info(f"[ERROR] Failed to execute request (requests): {e}")
            self.logger.exception(f"[ERROR] Failed to execute {e}-{action['id']}")
            self.action_result["status"] = "SUCCESS" 
            try:
                e = json.loads(f"{e}")
            except:
                e = f"{e}"

            try:
                self.action_result["result"] = json.dumps({
                    "success": False, 
                    "reason": f"Request error - failing silently. Details in detail section",
                    "details": f"{e}",
                })
            except json.decoder.JSONDecodeError as e:
                self.action_result["result"] = f"Request error: {e}"

        except Exception as e:
            self.logger.info(f"[ERROR] Failed to execute: {e}")
            self.logger.exception(f"[ERROR] Failed to execute {e}-{action['id']}")
            self.action_result["status"] = "FAILURE" 
            try:
                e = json.loads(f"{e}")
            except:
                e = f"{e}"

            self.action_result["result"] = json.dumps({
                "success": False,
                "reason": f"General exception in the app. See shuffle action logs for more details.",
                "details": f"{e}",
            })

        # Send the result :)
        self.action_result["completed_at"] = int(time.time_ns())
        self.send_result(self.action_result, headers, stream_path)

        #try:
        #    try:
        #        self.log_capture_string.flush()
        #    except Exception as e:
        #        print(f"[WARNING] Failed to flush logs (2): {e}") 
        #        pass

        #    self.log_capture_string.close()
        #except:
        #    print(f"[WARNING] Failed to close logs (2): {e}") 

        return

    @classmethod
    def run(cls, action=""):
        logging.basicConfig(format="{asctime} - {name} - {levelname}:{message}", style='{')
        logger = logging.getLogger(f"{cls.__name__}")
        logger.setLevel(logging.DEBUG)

        #logger.info("[DEBUG] Normal execution.")

        ##############################################

        exposed_port = os.getenv("SHUFFLE_APP_EXPOSED_PORT", "")
        #logger.info(f"[DEBUG] \"{runtime}\" - run indicates microservices. Port: \"{exposed_port}\"")
        if runtime == "run" and exposed_port != "":
            # Base port is 33334. Exposed port may differ based on discovery from Worker
            port = int(exposed_port)
            #logger.info(f"[DEBUG] Starting webserver on port {port} (same as exposed port)")
            from flask import Flask, request
            from waitress import serve

            flask_app = Flask(__name__)
            #flask_app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=5)

            #async def execute():
            @flask_app.route("/api/v1/health", methods=["GET", "POST"])
            def check_health():
                return "OK"

            @flask_app.route("/api/v1/run", methods=["POST"])
            def execute():
                if request.method == "POST":
                    requestdata = {}
                    try:
                        requestdata = json.loads(request.data)
                    except Exception as e:
                        return {
                            "success": False,
                            "reason": f"Invalid Action data {e}",
                        }

                    # Remaking class for each request

                    app = cls(redis=None, logger=logger, console_logger=logger)
                    extra_info = ""
                    try:
                        #asyncio.run(AppBase.run(action=requestdata), debug=True)
                        #value = json.dumps(value)
                        try:
                            app.full_execution = json.dumps(requestdata["workflow_execution"])
                        except Exception as e:
                            extra_info += f"\n{e}"

                        try:
                            app.action = requestdata["action"] 
                        except Exception as e:
                            extra_info += f"\n{e}"

                        try:
                            app.authorization = requestdata["authorization"]
                            app.current_execution_id = requestdata["execution_id"]
                        except Exception as e:
                            extra_info += f"\n{e}"

                        # BASE URL (backend)
                        try:
                            app.url = requestdata["url"]
                        except Exception as e:
                            extra_info += f"\n{e}"

                        # URL (worker)
                        try:
                            app.base_url = requestdata["base_url"]
                        except Exception as e:
                            extra_info += f"\n{e}"

                        #await 
                        app.execute_action(app.action)
                    except Exception as e:
                        return {
                            "success": False,
                            "reason": f"Problem in execution {e}",
                            "execution_issues": extra_info,
                        }

                    return {
                        "success": True,
                        "reason": "App successfully finished",
                        "execution_issues": extra_info,
                    }
                else:
                    return {
                        "success": False,
                        "reason": f"HTTP method {request.method} not allowed",
                    }

            logger.info(f"[DEBUG] Serving on port {port}")

            #flask_app.run(
            #    host="0.0.0.0", 
            #    port=port, 
            #    threaded=True, 
            #    processes=1, 
            #    debug=False,
            #)

            serve(
                flask_app, 
                host="0.0.0.0", 
                port=port, 
                threads=8,
                channel_timeout=30,
                expose_tracebacks=True,
                asyncore_use_poll=True,
            )
            #######################
        else:
            # Has to start like this due to imports in other apps
            # Move it outside everything?
            app = cls(redis=None, logger=logger, console_logger=logger)

            if isinstance(action, str):
                #logger.info("[DEBUG] Normal execution (env var). Action is a string.")
                pass
            elif isinstance(action, object):
                #logger.info("[DEBUG] OBJECT execution (cloud). Action is NOT a string.")
                app.action = action

                try:
                    app.authorization = action["authorization"]
                    app.current_execution_id = action["execution_id"]
                except:
                    pass

                # BASE URL (worker)
                try:
                    app.url = action["url"]
                except:
                    pass

                # Callback URL (backend)
                try:
                    app.base_url = action["base_url"]
                except:
                    pass
            else:
                #self.logger.info("ACTION TYPE (unhandled): %s" % type(action))
                pass

            app.execute_action(app.action)

if __name__ == "__main__":
    AppBase.run()
import hmac
import datetime
import json
import time
import markupsafe
import os
import re
import subprocess
import tempfile
import zipfile
import base64
import ipaddress
import hashlib
from io import StringIO
from contextlib import redirect_stdout
import random
import string

import xmltodict
from json2xml import json2xml
from json2xml.utils import readfromstring

from ioc_finder import find_iocs
from dateutil.parser import parse as dateutil_parser
from google.auth import crypt
from google.auth import jwt

import py7zr
import pyminizip
import rarfile
import requests
import tarfile
import binascii
import struct

import paramiko
import concurrent.futures
import multiprocessing


class Tools(AppBase):
    __version__ = "1.2.0"
    app_name = (
        "Shuffle Tools"  # this needs to match "name" in api.yaml for WALKOFF to work
    )

    def __init__(self, redis, logger, console_logger=None):
        """
        Each app should have this __init__ to set up Redis and logging.
        :param redis:
        :param logger:
        :param console_logger:
        """
        super().__init__(redis, logger, console_logger)

    def router(self):
        return "This action should be skipped"

    def base64_conversion(self, string, operation):
        if operation == "encode":
            # Try JSON decoding
            try:
                string = json.dumps(json.loads(string))
            except:
                pass

            encoded_bytes = base64.b64encode(str(string).encode("utf-8"))
            encoded_string = str(encoded_bytes, "utf-8")
            return encoded_string

        elif operation == "to image":
            # Decode the base64 into an image and upload it as a file
            decoded_bytes = base64.b64decode(string)

            # Make the bytes into unicode escaped bytes 
            # UnicodeDecodeError - 'utf-8' codec can't decode byte 0x89 in position 0: invalid start byte
            try:
                decoded_bytes = str(decoded_bytes, "utf-8")
            except:
                pass

            filename = "base64_image.png"
            file = {
                "filename": filename,
                "data": decoded_bytes, 
            }

            fileret = self.set_files([file])
            value = {"success": True, "filename": filename, "file_id": fileret}
            if len(fileret) == 1:
                value = {"success": True, "filename": filename, "file_id": fileret[0]}

            return value

        elif operation == "decode":

            if "-" in string:
                string = string.replace("-", "+", -1)

            if "_" in string:
                string = string.replace("_", "/", -1)

            # Fix padding
            if len(string) % 4 != 0:
                string += "=" * (4 - len(string) % 4)


            # For loop this. It's stupid.
            decoded_bytes = "" 
            try:
                decoded_bytes = base64.b64decode(string)
            except Exception as e:
                return json.dumps({
                    "success": False,
                    "reason": "Invalid Base64 - %s" % e,
                })

                #if "incorrect padding" in str(e).lower():
                #    try:
                #        decoded_bytes = base64.b64decode(string + "=")
                #    except Exception as e:
                #        if "incorrect padding" in str(e).lower():
                #            try:
                #                decoded_bytes = base64.b64decode(string + "==")
                #            except Exception as e:
                #                if "incorrect padding" in str(e).lower():
                #                    try:
                #                        decoded_bytes = base64.b64decode(string + "===")
                #                    except Exception as e:
                #                        if "incorrect padding" in str(e).lower():
                #                            return "Invalid Base64"


            try:
                decoded_bytes = str(decoded_bytes, "utf-8")
            except:
                pass

            # Check if json
            try:
                decoded_bytes = json.loads(decoded_bytes)
            except:
                pass

            return decoded_bytes

        return {
            "success": False,
            "reason": "Invalid operation",
        }

    def parse_list_internal(self, input_list):
        if isinstance(input_list, list):
            input_list = ",".join(input_list)

        try:
            input_list = json.loads(input_list)
            if isinstance(input_list, list):
                input_list = ",".join(input_list)
            else:
                return json.dumps(input_list)
        except:
            pass

        input_list = input_list.replace(", ", ",", -1)
        return input_list

    # This is an SMS function of Shuffle
    def send_sms_shuffle(self, apikey, phone_numbers, body):
        phone_numbers = self.parse_list_internal(phone_numbers)

        targets = [phone_numbers]
        if ", " in phone_numbers:
            targets = phone_numbers.split(", ")
        elif "," in phone_numbers:
            targets = phone_numbers.split(",")

        data = {"numbers": targets, "body": body}

        url = "https://shuffler.io/api/v1/functions/sendsms"
        headers = {"Authorization": "Bearer %s" % apikey}
        return requests.post(url, headers=headers, json=data, verify=False).text

    # This is an email function of Shuffle
    def send_email_shuffle(self, apikey, recipients, subject, body, attachments=""):
        recipients = self.parse_list_internal(recipients)


        targets = [recipients]
        if ", " in recipients:
            targets = recipients.split(", ")
        elif "," in recipients:
            targets = recipients.split(",")

        data = {
            "targets": targets, 
            "subject": subject, 
            "body": body, 
            "type": "alert",
            "email_app": True,
        }

        # Read the attachments
        if attachments != None and len(attachments) > 0:
            try:
                attachments = parse_list(attachments, splitter=",")
                files = []
                for item in attachments:
                    new_file = self.get_file(file_ids)
                    files.append(new_file)
            
                data["attachments"] = files
            except Exception as e:
                pass
                

        url = "https://shuffler.io/functions/sendmail"
        headers = {"Authorization": "Bearer %s" % apikey}
        return requests.post(url, headers=headers, json=data).text

    def repeat_back_to_me(self, call):
        return call

    def dedup_and_merge(self, key, value, timeout, set_skipped=True):
        timeout = int(timeout)
        key = str(key)

        set_skipped = True
        if str(set_skipped).lower() == "false":
            set_skipped = False
        else:
            set_skipped = True

        cachekey = "dedup-%s" % (key)
        response = {
            "success": False,
            "datastore_key": cachekey,
            "info": "All keys from the last %d seconds with the key '%s' have been merged. The result was set to SKIPPED in all other actions." % (timeout, key),
            "timeout": timeout,
            "original_value": value,
            "all_values": [],
        }

        found_cache = self.get_cache(cachekey)

        if found_cache["success"] == True and len(found_cache["value"]) > 0:
            if "value" in found_cache:
                if not str(found_cache["value"]).startswith("["):
                    found_cache["value"] = [found_cache["value"]]
                else:
                    try:
                        found_cache["value"] = json.loads(found_cache["value"])
                    except Exception as e:
                        self.logger.info("[ERROR] Failed parsing JSON: %s" % e)
            else:
                found_cache["value"] = []

            found_cache["value"].append(value)
            if "created" in found_cache:
                if found_cache["created"] + timeout + 3 < time.time():
                    set_skipped = False 
                    response["success"] = True
                    response["all_values"] = found_cache["value"]

                    self.delete_cache(cachekey)

                    return json.dumps(response)
                else:
                    self.logger.info("Dedup-key is already handled in another workflow with timeout %d" % timeout)

            self.set_cache(cachekey, json.dumps(found_cache["value"]))
            if set_skipped == True:
                self.action_result["status"] = "SKIPPED"
                self.action_result["result"] = json.dumps({
                    "status": False,
                    "reason": "Dedup-key is already handled in another workflow with timeout %d" % timeout,
                })

                self.send_result(self.action_result, {"Authorization": "Bearer %s" % self.authorization}, "/api/v1/streams")

            return found_cache

        parsedvalue = [value]
        resp = self.set_cache(cachekey, json.dumps(parsedvalue))

        self.logger.info("Sleeping for %d seconds while waiting for cache to fill up elsewhere" % timeout)
        time.sleep(timeout)
        found_cache = self.get_cache(cachekey)

        response["success"] = True
        response["all_values"] = found_cache["value"]

        self.delete_cache(cachekey)
        return json.dumps(response)


    # https://github.com/fhightower/ioc-finder
    def parse_file_ioc(self, file_ids, input_type="all"):
        def parse(data):
            try:
                iocs = find_iocs(str(data))
                newarray = []
                for key, value in iocs.items():
                    if input_type != "all":
                        if key not in input_type:
                            continue
                    if len(value) > 0:
                        for item in value:
                            if isinstance(value, dict):
                                for subkey, subvalue in value.items():
                                    if len(subvalue) > 0:
                                        for subitem in subvalue:
                                            data = {
                                                "data": subitem,
                                                "data_type": "%s_%s" % (key[:-1], subkey),
                                            }
                                            if data not in newarray:
                                                newarray.append(data)
                            else:
                                data = {"data": item, "data_type": key[:-1]}
                                if data not in newarray:
                                    newarray.append(data)
                for item in newarray:
                    if "ip" in item["data_type"]:
                        item["data_type"] = "ip"
                return {"success": True, "items": newarray}
            except Exception as excp:
                return {"success": False, "message": "{}".format(excp)}

        if input_type == "":
            input_type = "all"
        else:
            input_type = input_type.split(",")

        try:
            file_ids = eval(file_ids)  # nosec
        except SyntaxError:
            file_ids = file_ids
        except NameError:
            file_ids = file_ids

        return_value = None
        if type(file_ids) == str:
            return_value = parse(self.get_file(file_ids)["data"])
        elif type(file_ids) == list and type(file_ids[0]) == str:
            return_value = [
                parse(self.get_file(file_id)["data"]) for file_id in file_ids
            ]
        elif (
            type(file_ids) == list
            and type(file_ids[0]) == list
            and type(file_ids[0][0]) == str
        ):
            return_value = [
                [parse(self.get_file(file_id2)["data"]) for file_id2 in file_id]
                for file_id in file_ids
            ]
        else:
            return "Invalid input"
        return return_value

    def parse_list(self, items, splitter="\n"):
        # Check if it's already a list first
        try:
            newlist = json.loads(items)
            if isinstance(newlist, list):
                return newlist

        except Exception as e:
            self.logger.info("[WARNING] Parse error - fallback: %s" % e)

        if splitter == "":
            splitter = "\n"

        splititems = items.split(splitter)

        return str(splititems)

    def get_length(self, item):
        if item.startswith("[") and item.endswith("]"):
            try:
                item = item.replace("'", '"', -1)
                item = json.loads(item)
            except json.decoder.JSONDecodeError as e:
                self.logger.info("Parse error: %s" % e)

        return str(len(item))

    def set_json_key(self, json_object, key, value):
        if isinstance(json_object, str):
            try:
                json_object = json.loads(json_object)
            except json.decoder.JSONDecodeError as e:
                return {
                    "success": False,
                    "reason": "Item is not valid JSON"
                }

        if isinstance(json_object, list):
            if len(json_object) == 1:
                json_object = json_object[0]
            else:
                return {
                    "success": False,
                    "reason": "Item is valid JSON, but can't handle lists. Use .#"
                }

        #if not isinstance(json_object, object):
        #    return {
        #        "success": False,
        #        "reason": "Item is not valid JSON (2)"
        #    }

        
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.decoder.JSONDecodeError as e:
                pass

        # Handle JSON paths
        if "." in key:
            base_object = json.loads(json.dumps(json_object))
            #base_object.output.recipients.notificationEndpointIds = ... 

            keys = key.split(".")
            if len(keys) >= 1:
                first_object = keys[0]

            # This is awful :)
            buildstring = "base_object"
            for subkey in keys:
                buildstring += f"[\"{subkey}\"]" 

            buildstring += f" = {value}"

            #output = 
            exec(buildstring)
            json_object = base_object
            #json_object[first_object] = base_object
        else:
            json_object[key] = value

        return json_object

    def delete_json_keys(self, json_object, keys):
        keys = self.parse_list_internal(keys)

        splitdata = [keys]
        if ", " in keys:
            splitdata = keys.split(", ")
        elif "," in keys:
            splitdata = keys.split(",")

        for key in splitdata:
            key = key.strip()
            try:
                del json_object[key]
            except:
                self.logger.info(f"[ERROR] Key {key} doesn't exist")

        return json_object

    def replace_value(self, input_data, translate_from, translate_to, else_value=""):
        splitdata = [translate_from]
        if ", " in translate_from:
            splitdata = translate_from.split(", ")
        elif "," in translate_from:
            splitdata = translate_from.split(",")

        if isinstance(input_data, list) or isinstance(input_data, dict):
            input_data = json.dumps(input_data)

        to_return = input_data
        if isinstance(input_data, str):
            found = False
            for item in splitdata:
                item = item.strip()
                if item in input_data:
                    input_data = input_data.replace(item, translate_to)
                    found = True

            if not found and len(else_value) > 0:
                input_data = else_value

        if input_data.lower() == "false":
            return False
        elif input_data.lower() == "true":
            return True

        return input_data

    def replace_value_from_dictionary(self, input_data, mapping, default_value=""):
        if isinstance(mapping, str):
            try:
                mapping = json.loads(mapping)
            except json.decoder.JSONDecodeError as e:
                return {
                    "success": False,
                    "reason": "Mapping is not valid JSON: %s" % e,
                }

        for key, value in mapping.items():
            try:
                input_data = input_data.replace(key, str(value), -1)
            except:
                self.logger.info(f"Failed mapping output data for key {key}")

        return input_data 

    # Changed with 1.1.0 to run with different returns 
    def regex_capture_group(self, input_data, regex):
        try:
            returnvalues = {
                "success": True,
            }

            matches = re.findall(regex, input_data)
            found = False
            for item in matches:
                if isinstance(item, str):
                    found = True 
                    name = "group_0" 
                    try:
                        returnvalues[name].append(item)
                    except:
                        returnvalues[name] = [item]

                else:
                    for i in range(0, len(item)):
                        found = True 
                        name = "group_%d" % i
                        try:
                            returnvalues[name].append(item[i])
                        except:
                            returnvalues[name] = [item[i]]

            returnvalues["found"] = found

            return returnvalues
        except re.error as e:
            return {
                "success": False,
                "reason": "Bad regex pattern: %s" % e,
            }

    def regex_replace(
        self, input_data, regex, replace_string="", ignore_case="False"
    ):

        if ignore_case.lower().strip() == "true":
            return re.sub(regex, replace_string, input_data, flags=re.IGNORECASE)
        else:
            return re.sub(regex, replace_string, input_data)

    def execute_python(self, code):
        if len(code) == 36 and "-" in code:
            filedata = self.get_file(code)
            if filedata["success"] == False:
                return {
                    "success": False,
                    "message": f"Failed to get file for ID {code}",
                }

            if ".py" not in filedata["filename"]:
                return {
                    "success": False,
                    "message": f"Filename needs to contain .py",
                }


        # Write the code to a file
        # 1. Take the data into a file
        # 2. Subprocess execute file?
        try:
            f = StringIO()
            def custom_print(*args, **kwargs):
                return print(*args, file=f, **kwargs)
            
            #with redirect_stdout(f): # just in case
            # Add globals in it too
            globals_copy = globals().copy()
            globals_copy["print"] = custom_print

            # Add self to globals_copy
            for key, value in locals().copy().items():
                if key not in globals_copy:
                    globals_copy[key] = value

            globals_copy["self"] = self

            exec(code, globals_copy)

            s = f.getvalue()
            f.close() # why: https://www.youtube.com/watch?v=6SA6S9Ca5-U

            #try:
            #    s = s.encode("utf-8")
            #except Exception as e:

            try:
                return {
                    "success": True,
                    "message": json.loads(s.strip()),
                }
            except Exception as e:
                try:
                    return {
                        "success": True,
                        "message": s.strip(),
                    }
                except Exception as e:
                    return {
                        "success": True,
                        "message": s,
                    }
                
        except Exception as e:
            return {
                "success": False,
                "message": f"exception: {e}",
            }

    def execute_bash(self, code, shuffle_input):
        process = subprocess.Popen(
            code,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True,  # nosec
        )
        stdout = process.communicate()
        item = ""
        if len(stdout[0]) > 0:
            item = stdout[0]
        else:
            self.logger.info(f"[ERROR] FAILED to run bash command {code}!")
            item = stdout[1]

        try:
            ret = item.decode("utf-8")
            return ret
        except Exception:
            return item

        return item

    # Check if wildcardstring is in all_ips and support * as wildcard
    def check_wildcard(self, wildcardstring, matching_string):
        wildcardstring = str(wildcardstring.lower())
        if wildcardstring in str(matching_string).lower():
            return True
        else:
            wildcardstring = wildcardstring.replace(".", "\\.")
            wildcardstring = wildcardstring.replace("*", ".*")

            if re.match(wildcardstring, str(matching_string).lower()):
                return True

        return False

    def filter_list(self, input_list, field, check, value, opposite):

        # Remove hashtags on the fly
        # E.g. #.fieldname or .#.fieldname

        flip = False
        if str(opposite).lower() == "true":
            flip = True

        try:
            #input_list = eval(input_list)  # nosec
            input_list = json.loads(input_list)
        except Exception:
            try:
                input_list = input_list.replace("'", '"', -1)
                input_list = json.loads(input_list)
            except Exception:
                self.logger.info("[WARNING] Error parsing string to array. Continuing anyway.")

        # Workaround D:
        if not isinstance(input_list, list):
            return {
                "success": False,
                "reason": "Error: input isnt a list. Please use conditions instead if using JSON.", 
                "valid": [],
                "invalid": [],
            }

            input_list = [input_list]

        if str(value).lower() == "null" or str(value).lower() == "none":
            value = "none"

        found_items = []
        new_list = []
        failed_list = []
        for item in input_list:
            try:
                try:
                    item = json.loads(item)
                except Exception:
                    pass

                # Support for nested dict key
                tmp = item
                if field and field.strip() != "":
                    for subfield in field.split("."):
                        tmp = tmp[subfield]

                if isinstance(tmp, dict) or isinstance(tmp, list):
                    try:
                        tmp = json.dumps(tmp)
                    except json.decoder.JSONDecodeError as e:
                        pass


                # EQUALS JUST FOR STR
                if check == "equals":
                    # Mostly for bools
                    # value = tmp.lower()

                    if str(tmp).lower() == str(value).lower():
                        new_list.append(item)
                    else:
                        failed_list.append(item)

                elif check == "equals any of":
                    checklist = value.split(",")
                    found = False
                    for subcheck in checklist:
                        subcheck = str(subcheck).strip()

                        #ext.lower().strip() == value.lower().strip()
                        if type(tmp) == list and subcheck in tmp:
                            new_list.append(item)
                            found = True
                            break
                        elif type(tmp) == str and tmp == subcheck:
                            new_list.append(item)
                            found = True
                            break
                        elif type(tmp) == int and str(tmp) == subcheck:
                            new_list.append(item)
                            found = True
                            break
                        else:
                            if str(tmp) == str(subcheck):
                                new_list.append(item)
                                found = True
                                break

                    if not found:
                        failed_list.append(item)

                # IS EMPTY FOR STR OR LISTS
                elif check == "is empty":
                    if str(tmp) == "[]":
                        tmp = []

                    if str(tmp) == "{}":
                        tmp = []

                    if type(tmp) == list and len(tmp) == 0:
                        new_list.append(item)
                    elif type(tmp) == str and not tmp:
                        new_list.append(item)
                    else:
                        failed_list.append(item)

                # STARTS WITH = FOR STR OR [0] FOR LIST
                elif check == "starts with":
                    if type(tmp) == list and tmp[0] == value:
                        new_list.append(item)
                    elif type(tmp) == str and tmp.startswith(value):
                        new_list.append(item)
                    else:
                        failed_list.append(item)

                # ENDS WITH = FOR STR OR [-1] FOR LIST
                elif check == "ends with":
                    if type(tmp) == list and tmp[-1] == value:
                        new_list.append(item)
                    elif type(tmp) == str and tmp.endswith(value):
                        new_list.append(item)
                    else:
                        failed_list.append(item)

                # CONTAINS FIND FOR LIST AND IN FOR STR
                elif check == "contains":
                    #if str(value).lower() in str(tmp).lower():
                    if str(value).lower() in str(tmp).lower() or self.check_wildcard(value, tmp): 
                        new_list.append(item)
                    else:
                        failed_list.append(item)

                elif check == "contains any of":
                    value = self.parse_list_internal(value)
                    checklist = value.split(",")
                    found = False
                    for checker in checklist:
                        if str(checker).lower() in str(tmp).lower() or self.check_wildcard(checker, tmp): 
                            new_list.append(item)
                            found = True
                            break

                    if not found:
                        failed_list.append(item)

                # CONTAINS FIND FOR LIST AND IN FOR STR
                elif check == "field is unique":
                    if tmp.lower() not in found_items:
                        new_list.append(item)
                        found_items.append(tmp.lower())
                    else:
                        failed_list.append(item)

                # CONTAINS FIND FOR LIST AND IN FOR STR
                elif check == "larger than":
                    list_set = False
                    try:
                        if str(tmp).isdigit() and str(value).isdigit():
                            if int(tmp) > int(value):
                                new_list.append(item)
                                list_set = True
                    except AttributeError as e:
                        pass

                    try:
                        value = len(json.loads(value))
                    except Exception as e:
                        pass

                    try:
                        # Check if it's a list in autocast and if so, check the length
                        if len(json.loads(tmp)) > int(value):
                            new_list.append(item)
                            list_set = True
                    except Exception as e:
                        pass

                    if not list_set:
                        failed_list.append(item)
                elif check == "less than":
                    # Old
                    #if int(tmp) < int(value):
                    #    new_list.append(item)
                    #else:
                    #    failed_list.append(item)

                    list_set = False
                    try:
                        if str(tmp).isdigit() and str(value).isdigit():
                            if int(tmp) < int(value):
                                new_list.append(item)
                                list_set = True
                    except AttributeError as e:
                        pass

                    try:
                        value = len(json.loads(value))
                    except Exception as e:
                        pass

                    try:
                        # Check if it's a list in autocast and if so, check the length
                        if len(json.loads(tmp)) < int(value):
                            new_list.append(item)
                            list_set = True
                    except Exception as e:
                        pass

                    if not list_set:
                        failed_list.append(item)

                elif check == "in cache key":
                    ret = self.check_cache_contains(value, tmp, "true")
                    if ret["success"] == True and ret["found"] == True:
                        new_list.append(item)
                    else:
                        failed_list.append(item)

                    #return {
                    #    "success": True,
                    #    "found": False,
                    #    "key": key,
                    #    "value": new_value,
                    #}

                # SINGLE ITEM COULD BE A FILE OR A LIST OF FILES
                elif check == "files by extension":
                    if type(tmp) == list:
                        file_list = []

                        for file_id in tmp:
                            filedata = self.get_file(file_id)
                            _, ext = os.path.splitext(filedata["filename"])
                            if (ext.lower().strip() == value.lower().strip()):
                                file_list.append(file_id)
                            # else:
                            #    failed_list.append(file_id)

                        tmp = item
                        if field and field.strip() != "":
                            for subfield in field.split(".")[:-1]:
                                tmp = tmp[subfield]
                            tmp[field.split(".")[-1]] = file_list
                            new_list.append(item)
                        else:
                            new_list = file_list
                        # else:
                        #    failed_list = file_list

                    elif type(tmp) == str:
                        filedata = self.get_file(tmp)
                        _, ext = os.path.splitext(filedata["filename"])
                        if ext.lower().strip() == value.lower().strip():
                            new_list.append(item)
                        else:
                            failed_list.append(item)

            except Exception as e:
                failed_list.append(item)
            # return

        if flip:
            tmplist = new_list
            new_list = failed_list
            failed_list = tmplist

        try:
            return json.dumps(
                {
                    "success": True,
                    "valid": new_list,
                    "invalid": failed_list,
                }
            )
            # new_list = json.dumps(new_list)
        except json.decoder.JSONDecodeError as e:
            return json.dumps(
                {
                    "success": False,
                    "reason": "Failed parsing filter list output" + e,
                }
            )

        return new_list

    #def multi_list_filter(self, input_list, field, check, value):
    #    input_list = input_list.replace("'", '"', -1)
    #    input_list = json.loads(input_list)

    #    fieldsplit = field.split(",")
    #    if ", " in field:
    #        fieldsplit = field.split(", ")

    #    valuesplit = value.split(",")
    #    if ", " in value:
    #        valuesplit = value.split(", ")

    #    checksplit = check.split(",")
    #    if ", " in check:
    #        checksplit = check.split(", ")

    #    new_list = []
    #    for list_item in input_list:
    #        list_item = json.loads(list_item)

    #        index = 0
    #        for check in checksplit:
    #            if check == "equals":
    #                self.logger.info(
    #                    "Checking %s vs %s"
    #                    % (list_item[fieldsplit[index]], valuesplit[index])
    #                )
    #                if list_item[fieldsplit[index]] == valuesplit[index]:
    #                    new_list.append(list_item)

    #        index += 1

    #    # "=",
    #    # "equals",
    #    # "!=",
    #    # "does not equal",
    #    # ">",
    #    # "larger than",
    #    # "<",
    #    # "less than",
    #    # ">=",
    #    # "<=",
    #    # "startswith",
    #    # "endswith",
    #    # "contains",
    #    # "re",
    #    # "matches regex",

    #    try:
    #        new_list = json.dumps(new_list)
    #    except json.decoder.JSONDecodeError as e:
    #        return "Failed parsing filter list output" % e

    #    return new_list

    # Gets the file's metadata, e.g. md5
    def get_file_meta(self, file_id):
        headers = {
            "Authorization": "Bearer %s" % self.authorization,
        }

        ret = requests.get(
            "%s/api/v1/files/%s?execution_id=%s"
            % (self.url, file_id, self.current_execution_id),
            headers=headers,
            verify=False,
        )

        return ret.text

    # Use data from AppBase to talk to backend
    def delete_file(self, file_id):
        headers = {
            "Authorization": "Bearer %s" % self.authorization,
        }

        ret = requests.delete(
            "%s/api/v1/files/%s?execution_id=%s"
            % (self.url, file_id, self.current_execution_id),
            headers=headers,
            verify=False,
        )
        return ret.text

    def create_file(self, filename, data):
        try:
            if str(data).startswith("b'") and str(data).endswith("'"):
                data = data[2:-1]
            if str(data).startswith("\"") and str(data).endswith("\""):
                data = data[2:-1]
        except Exception as e:
            self.logger.info(f"Exception: {e}")

        try:
            #if not isinstance(data, str) and not isinstance(data, int) and not isinstance(float) and not isinstance(data, bool):
            if isinstance(data, dict) or isinstance(data, list):
                data = json.dumps(data)
        except:
            pass

        filedata = {
            "filename": filename,
            "data": data,
        }

        fileret = self.set_files([filedata])
        value = {"success": True, "filename": filename, "file_id": fileret}
        if len(fileret) == 1:
            value = {"success": True, "filename": filename, "file_id": fileret[0]}

        return value 

    # Input is WAS a file, hence it didn't get the files 
    def list_file_category_ids(self, file_category):
        return self.get_file_category_ids(file_category)

    # Input is WAS a file, hence it didn't get the files 
    def get_file_value(self, filedata):
        filedata = self.get_file(filedata)
        if filedata is None:
            return {
                "success": False,
                "reason": "File not found",
            }

        if "data" not in filedata:
            return {
                "success": False,
                "reason": "File content not found. File might be empty or not exist",
            }

        try:
            return filedata["data"].decode()
        except:
            try:
                return filedata["data"].decode("utf-16")
            except:
                try:
                    return filedata["data"].decode("utf-8")
                except:
                    try:
                        return filedata["data"].decode("latin-1")
                    except:
                        return {
                            "success": False,
                            "reason": "Got the file, but the encoding can't be printed",
                            "size": len(filedata["data"]),
                        }

    def download_remote_file(self, url, custom_filename=""):
        ret = requests.get(url, verify=False)  # nosec
        filename = url.split("/")[-1]
        if "?" in filename:
            filename = filename.split("?")[0]

        if custom_filename and len(str(custom_filename)) > 0:
            filename = custom_filename

        fileret = self.set_files(
            [
                {
                    "filename": filename,
                    "data": ret.content,
                }
            ]
        )

        if len(fileret) > 0:
            value = {"success": True, "file_id": fileret[0]}
        else:
            value = {"success": False, "reason": "No files downloaded"}

        return value

    
    def extract_archive(self, file_id, fileformat="zip", password=None):
        try:
            return_data = {"success": False, "files": []}
            to_be_uploaded = []
            item = self.get_file(file_id)
            return_ids = None

            with tempfile.TemporaryDirectory() as tmpdirname:

                # Get archive and save phisically
                with open(os.path.join(tmpdirname, "archive"), "wb") as f:
                    f.write(item["data"])

                # Grab files before, upload them later

                # Zipfile for zipped archive
                if fileformat.strip().lower() == "zip":
                    try:
                        with zipfile.ZipFile(os.path.join(tmpdirname, "archive")) as z_file:
                            if password:
                                z_file.setpassword(bytes(password.encode()))

                            for member in z_file.namelist():
                                filename = os.path.basename(member)
                                if not filename:
                                    continue

                                source = z_file.open(member)
                                to_be_uploaded.append(
                                    {"filename": source.name.split("/")[-1], "data": source.read()}
                                )

                                return_data["success"] = True
                    except (zipfile.BadZipFile, Exception):
                        return_data["files"].append(
                            {
                                "success": False,
                                "file_id": file_id,
                                "filename": item["filename"],
                                "message": "File is not a valid zip archive",
                            }
                        )

                elif fileformat.strip().lower() == "rar":
                    try:
                        with rarfile.RarFile(
                            os.path.join(tmpdirname, "archive")
                        ) as z_file:
                            if password:
                                z_file.setpassword(password)
                            for member in z_file.namelist():
                                filename = os.path.basename(member)
                                if not filename:
                                    continue

                                source = z_file.open(member)
                                to_be_uploaded.append(
                                    {"filename": source.name.split("/")[-1], "data": source.read()}
                                )

                                return_data["success"] = True
                    except Exception:
                        return_data["files"].append(
                            {
                                "success": False,
                                "file_id": file_id,
                                "filename": item["filename"],
                                "message": "File is not a valid rar archive",
                            }
                        )

                elif fileformat.strip().lower() == "tar":
                    try:
                        with tarfile.open(
                            os.path.join(tmpdirname, "archive"), mode="r"
                        ) as z_file:
                            for member in z_file.getnames():
                                member_files = z_file.extractfile(member)

                                if not member_files:
                                    continue

                                to_be_uploaded.append(
                                    {
                                        "filename": member.split("/")[-1],
                                        "data": member_files.read(),
                                    }
                                )
                            return_data["success"] = True
                    except Exception as e:
                        return_data["files"].append(
                            {
                                "success": False,
                                "file_id": file_id,
                                "filename": item["filename"],
                                "message": f"{e}",
                            }
                        )
                elif fileformat.strip().lower() == "tar.gz":
                    try:
                        with tarfile.open(os.path.join(tmpdirname, "archive"), mode="r:gz") as z_file:
                            for member in z_file.getnames():
                                member_files = z_file.extractfile(member)

                                if not member_files:
                                    continue

                                to_be_uploaded.append(
                                    {
                                        "filename": member.split("/")[-1],
                                        "data": member_files.read(),
                                    }
                                )

                            return_data["success"] = True

                    except Exception as e:
                        return_data["files"].append(
                            {
                                "success": False,
                                "file_id": file_id,
                                "filename": item["filename"],
                                "message": f"{e}",
                            }
                        )

                elif fileformat.strip().lower() == "7zip":
                    try:
                        with py7zr.SevenZipFile(
                            os.path.join(tmpdirname, "archive"),
                            mode="r",
                            password=password if password else None,
                        ) as z_file:
                            for filename, source in z_file.readall().items():
                                # Removes paths
                                filename = filename.split("/")[-1]
                                to_be_uploaded.append(
                                    {
                                        "filename": item["filename"].split("/")[-1],
                                        "data": source.read(),
                                    }
                                )
                                return_data["success"] = True
                    except Exception:
                        return_data["files"].append(
                            {
                                "success": False,
                                "file_id": file_id,
                                "filename": item["filename"],
                                "message": "File is not a valid 7zip archive",
                            }
                        )
                else:
                    return "No such format: %s" % fileformat

            if len(to_be_uploaded) > 0:
                return_ids = self.set_files(to_be_uploaded)

                for i in range(len(return_ids)):
                    return_data["archive_id"] = file_id
                    try:
                        return_data["files"].append(
                            {
                                "success": True,
                                "file_id": return_ids[i],
                                "filename": to_be_uploaded[i]["filename"],
                            }
                        )
                    except:
                        return_data["files"].append(
                            {
                                "success": True,
                                "file_id": return_ids[i],
                            }
                        )
            else:
                return_data["success"] = False
                return_data["files"].append(
                    {
                        "success": False,
                        "filename": "No data in archive",
                        "message": "Archive is empty",
                    }
                )

            return return_data

        except Exception as excp:
            return {"success": False, "message": "%s" % excp}

    def create_archive(self, file_ids, fileformat, name, password=None):
        try:
            # TODO: will in future support multiple files instead of string ids?
            if isinstance(file_ids, str):
                file_ids = file_ids.split()
            elif isinstance(file_ids, list):
                file_ids = file_ids
            else:
                return {
                    "success": False,
                    "reason": "Bad file_ids. Example: file_13eea837-c56a-4d52-a067-e673c7186483",
                }

            if len(file_ids) == 0:
                return {
                    "success": False,
                    "reason": "Make sure to send valid file ids. Example: file_13eea837-c56a-4d52-a067-e673c7186483,file_13eea837-c56a-4d52-a067-e673c7186484",
                }

            # GET all items from shuffle
            items = [self.get_file(file_id) for file_id in file_ids]

            if len(items) == 0:
                return "No file to inflate"

            # Dump files on disk, because libs want path :(
            with tempfile.TemporaryDirectory() as tmpdir:
                paths = []
                for item in items:
                    with open(os.path.join(tmpdir, item["filename"]), "wb") as f:
                        f.write(item["data"])
                        paths.append(os.path.join(tmpdir, item["filename"]))

                # Create archive temporary
                with tempfile.NamedTemporaryFile() as archive:

                    if fileformat == "zip":
                        archive_name = "archive.zip" if not name else name
                        pyminizip.compress_multiple(
                            paths, [], archive.name, password, 5
                        )

                    elif fileformat == "7zip":
                        archive_name = "archive.7z" if not name else name
                        with py7zr.SevenZipFile(
                            archive.name,
                            "w",
                            password=password if len(password) > 0 else None,
                        ) as sz_archive:
                            for path in paths:
                                sz_archive.write(path)

                    else:
                        return "Format {} not supported".format(fileformat)

                    return_id = self.set_files(
                        [{"filename": archive_name, "data": open(archive.name, "rb")}]
                    )

                    if len(return_id) == 1:
                        # Returns the first file's ID
                        return {"success": True, "file_id": return_id[0]}
                    else:
                        return {
                            "success": False,
                            "message": "Upload archive returned {}".format(return_id),
                        }

        except Exception as excp:
            return {"success": False, "message": excp}

    def add_list_to_list(self, list_one, list_two):
        if not isinstance(list_one, list) and not isinstance(list_one, dict): 
            if not list_one or list_one == " " or list_one == "None" or list_one == "null":
                list_one = "[]"

            try:
                list_one = json.loads(list_one)
            except json.decoder.JSONDecodeError as e:
                if list_one == None:
                    list_one = []
                else:
                    return {
                        "success": False,
                        "reason": f"List one is not a valid list: {list_one}" 
                    }

        if not isinstance(list_two, list) and not isinstance(list_two, dict):
            if not list_two or list_two == " " or list_two == "None" or list_two == "null":
                list_two = "[]"

            try:
                list_two = json.loads(list_two)
            except json.decoder.JSONDecodeError as e:
                if list_one == None:
                    list_one = []
                else:
                    return {
                        "success": False,
                        "reason": f"List two is not a valid list: {list_two}"
                    }

        if isinstance(list_one, dict):
            list_one = [list_one]
        if isinstance(list_two, dict):
            list_two = [list_two]

        for item in list_two:
            list_one.append(item)

        return list_one

    def diff_lists(self, list_one, list_two):
        if isinstance(list_one, str):
            try:
                list_one = json.loads(list_one)
            except json.decoder.JSONDecodeError as e:
                return {
                    "success": False,
                    "reason": "list_one is not a valid list."
                }

        if isinstance(list_two, str):
            try:
                list_two = json.loads(list_two)
            except json.decoder.JSONDecodeError as e:
                return {
                    "success": False,
                    "reason": "list_two is not a valid list."
                }

        def diff(li1, li2):
            try:
                return list(set(li1) - set(li2)) + list(set(li2) - set(li1))
            except TypeError as e:
                # Bad json diffing - at least order doesn't matter :)
                not_found = []
                for item in list_one:
                    #item = sorted(item.items())
                    if item in list_two:
                        pass
                    else:
                        not_found.append(item)

                for item in list_two:
                    if item in list_one:
                        pass
                    else:
                        if item not in not_found:
                            not_found.append(item)

                return not_found

        newdiff = diff(list_one, list_two)
        parsed_diff = []
        for item in newdiff:
            if not item:
                continue

            parsed_diff.append(item)

        return {
            "success": True,
            "diff": newdiff,
        }


    def merge_lists(self, list_one, list_two, set_field="", sort_key_list_one="", sort_key_list_two=""):
        if isinstance(list_one, str):
            try:
                list_one = json.loads(list_one)
            except json.decoder.JSONDecodeError as e:
                pass

        if isinstance(list_two, str):
            try:
                list_two = json.loads(list_two)
            except json.decoder.JSONDecodeError as e:
                pass

        if not isinstance(list_one, list) or not isinstance(list_two, list):
            if isinstance(list_one, dict) and isinstance(list_two, dict):
                for key, value in list_two.items():
                    list_one[key] = value
            
                return list_one

            return {"success": False, "message": "Both input lists need to be valid JSON lists."}

        if len(list_one) != len(list_two):
            return {"success": False, "message": "Lists length must be the same. %d vs %d" % (len(list_one), len(list_two))}

        if len(sort_key_list_one) > 0:
            try:
                list_one = sorted(list_one, key=lambda k: k.get(sort_key_list_one), reverse=True)
            except:
                pass

        if len(sort_key_list_two) > 0:
            try:
                list_two = sorted(list_two, key=lambda k: k.get(sort_key_list_two), reverse=True)
            except:
                pass

        # Loops for each item in sub array and merges items together
        # List one is being overwritten
        base_key = "shuffle_auto_merge"
        try:
            for i in range(len(list_one)):
                if isinstance(list_two[i], dict):
                    for key, value in list_two[i].items():
                        list_one[i][key] = value
                elif isinstance(list_two[i], str) and list_two[i] == "":
                    continue
                elif isinstance(list_two[i], str) or isinstance(list_two[i], int) or isinstance(list_two[i], bool):
                    if len(set_field) == 0:
                        list_one[i][base_key] = list_two[i]
                    else:
                        set_field = set_field.replace(" ", "_", -1)
                        list_one[i][set_field] = list_two[i]
        except Exception as e:
            return {
                "success": False,
                "reason": "An error occurred while merging the lists. PS: List one can NOT be a list of integers. If this persists, contact us at support@shuffler.io",
                "exception": f"{e}",
            }

        return list_one

    def merge_json_objects(self, list_one, list_two, set_field="", sort_key_list_one="", sort_key_list_two=""):
        return self.merge_lists(list_one, list_two, set_field=set_field, sort_key_list_one=sort_key_list_one, sort_key_list_two=sort_key_list_two)

    def fix_json(self, json_data):
        try:
            deletekeys = []
            copied_dict = json_data.copy()

            for key, value in copied_dict.items():
                if "@" in key or "." in key or " " in key:
                    deletekeys.append(key)

                    key = key.replace("@", "", -1)
                    key = key.replace(".", "", -1)
                    key = key.replace(" ", "_", -1)
                    json_data[key] = value

                if isinstance(value, dict):
                    json_data[key] = self.fix_json(value)
                else:
                    json_data[key] = value

                #elif isinstance(value, list):
                #    json_data[key] = value
                #else:
                #    json_data[key] = value
                #    #for item in json_data[key]:
                #    #    if isinstance(item, dict):
                #    #        json_data[
                    
            for key in deletekeys:
                del json_data[key]

        except Exception as e:
            pass

        return json_data

    def xml_json_convertor(self, convertto, data):
        if isinstance(data, dict) or isinstance(data, list):
            try:
                data = json.dumps(data)
            except:
                pass

        try:
            if convertto == "json":
                data = data.replace(" encoding=\"utf-8\"", " ")
                ans = xmltodict.parse(data)
                ans = self.fix_json(ans)
                json_data = json.dumps(ans)

                return json_data
            else:
                ans = readfromstring(data)
                return json2xml.Json2xml(ans, wrapper="all", pretty=True).to_xml()
        except Exception as e:
            return {
                "success": False,
                "input": data,
                "reason": f"{e}"
            }

    def date_to_epoch(self, input_data, date_field, date_format):
        if isinstance(input_data, str):
            result = json.loads(input_data)
        else:
            result = input_data

        # https://docs.python.org/3/library/datetime.html#strftime-strptime-behavior
        epoch = datetime.datetime.strptime(result[date_field], date_format).strftime(
            "%s"
        )
        result["epoch"] = epoch
        return result

    def compare_relative_date(
        self, timestamp, date_format, equality_test, offset, units, direction
    ):
        if timestamp== "None":
            return False
   
        if date_format == "autodetect":
            input_dt = dateutil_parser(timestamp).replace(tzinfo=None)
        elif date_format != "%s":
            input_dt = datetime.datetime.strptime(timestamp, date_format)
        else:
            input_dt = datetime.datetime.utcfromtimestamp(float(timestamp))

        offset = int(offset)
        if units == "seconds":
            delta = datetime.timedelta(seconds=offset)
        elif units == "minutes":
            delta = datetime.timedelta(minutes=offset)
        elif units == "hours":
            delta = datetime.timedelta(hours=offset)
        elif units == "days":
            delta = datetime.timedelta(days=offset)

        utc_format = date_format
        if utc_format.endswith("%z"):
            utc_format = utc_format.replace("%z", "Z")

        #if date_format != "%s" and date_format != "autodetect":
        if date_format == "autodetect":
            formatted_dt = datetime.datetime.utcnow() + delta
        elif date_format != "%s":
            formatted_dt = datetime.datetime.strptime(
                datetime.datetime.utcnow().strftime(utc_format), date_format
            )

        else:
            formatted_dt = datetime.datetime.utcnow()

        if date_format == "autodetect":
            comparison_dt = formatted_dt
        elif direction == "ago":
            comparison_dt = formatted_dt - delta
            #formatted_dt - delta
            #comparison_dt = datetime.datetime.utcnow()
        else:
            comparison_dt = formatted_dt + delta
            #comparison_dt = datetime.datetime.utcnow()

        diff = int((input_dt - comparison_dt).total_seconds())

        if units == "seconds":
            diff = diff
        elif units == "minutes":
            diff = int(diff/60)
        elif units == "hours":
            diff = int(diff/3600)
        elif units == "days":
            diff = int(diff/86400)
        elif units == "week":
            diff = int(diff/604800)

        result = False
        if equality_test == ">":
            result = 0 > diff
            if direction == "ahead":
                result = not (result)

        elif equality_test == "<":
            result = 0 < diff
            if direction == "ahead":
                result = not (result)

        elif equality_test == "=":
            result = diff == 0 

        elif equality_test == "!=":
            result = diff != 0
        elif equality_test == ">=":
            result = 0 >= diff
            if direction == "ahead" and diff != 0:
                result = not (result)
        elif equality_test == "<=":
            result = 0 <= diff
            if direction == "ahead" and diff != 0:
                result = not (result)

        parsed_string = "%s %s %s %s" % (equality_test, offset, units, direction)
        newdiff = diff
        if newdiff < 0:
            newdiff = newdiff*-1

        return {
            "success": True,
            "date": timestamp,
            "check": parsed_string,
            "result": result,
            "diff": {
                "days": int(int(newdiff)/86400),
            },
        }


    def run_math_operation(self, operation):
        result = eval(operation)
        return result

    # This is kind of stupid
    def escape_html(self, input_data):
        if isinstance(input_data, str):
            mapping = json.loads(input_data)
        else:
            mapping = input_data

        result = markupsafe.escape(mapping)
        return mapping

    def check_cache_contains(self, key, value, append):
        org_id = self.full_execution["workflow"]["execution_org"]["id"]
        url = "%s/api/v1/orgs/%s/get_cache" % (self.url, org_id)
        data = {
            "workflow_id": self.full_execution["workflow"]["id"],
            "execution_id": self.current_execution_id,
            "authorization": self.authorization,
            "org_id": org_id,
            "search": str(value),
            "key": key,
        }

        allvalues = {}
        try:
            for item in self.local_storage:
                if item["execution_id"] == self.current_execution_id and item["key"] == key:
                    # Max keeping the local cache properly for 5 seconds due to workflow continuations
                    elapsed_time = time.time() - item["time_set"]
                    if elapsed_time > 5:
                        break

                    allvalues = item["data"]

        except Exception as e:
            print("[ERROR] Failed cache contains for current execution id local storage: %s" % e)

        if isinstance(value, dict) or isinstance(value, list):
            try:
                value = json.dumps(value)
            except Exception as e:
                pass
        
        if not isinstance(value, str):
            value = str(value)

        data["search"] = value

        if str(append).lower() == "true":
            append = True
        else:
            append = False 

        if "success" not in allvalues:
            get_response = requests.post(url, json=data, verify=False)

        try:
            if "success" not in allvalues:
                allvalues = get_response.json()

            try:
                if allvalues["value"] == None or allvalues["value"] == "null":
                    allvalues["value"] = "[]"
            except:
                pass

            if allvalues["success"] == False:
                if append == True:
                    new_value = [str(value)]
                    data["value"] = json.dumps(new_value)

                    set_url = "%s/api/v1/orgs/%s/set_cache" % (self.url, org_id)
                    set_response = requests.post(set_url, json=data, verify=False)
                    try:
                        allvalues = set_response.json()
                        #allvalues["key"] = key
                        #return allvalues


                        return {
                            "success": True,
                            "found": False,
                            "key": key,
                            "search": value,
                            "value": new_value,
                        }
                    except Exception as e:
                        return {
                            "success": False,
                            "found": False,
                            "key": key,
                            "search": value,
                            "reason": "Failed to find key, and failed to append",
                        }
                else:
                    return {
                        "success": True,
                        "found": False,
                        "key": key,
                        "search": value,
                        "reason": "Not appended, not found",
                    }
            else:
                if allvalues["value"] == None or allvalues["value"] == "null":
                    allvalues["value"] = "[]"

                allvalues["value"] = str(allvalues["value"])

                try:
                    parsedvalue = json.loads(allvalues["value"])
                except json.decoder.JSONDecodeError as e:
                    parsedvalue = [str(allvalues["value"])]
                except Exception as e:
                    parsedvalue = [str(allvalues["value"])]

                try:
                    for item in parsedvalue:
                        #return "%s %s" % (item, value)
                        if item == value:
                            if not append:
                                try:
                                    newdata = json.loads(json.dumps(data))
                                    newdata["time_set"] = time.time()
                                    newdata["data"] = allvalues
                                    self.local_storage.append(newdata)
                                except Exception as e:
                                    print("[ERROR] Failed in local storage append: %s" % e)

                                return {
                                    "success": True,
                                    "found": True,
                                    "reason": "Found and not appending!",
                                    "key": key,
                                    "search": value,
                                    "value": json.loads(allvalues["value"]),
                                }
                            else:
                                return {
                                    "success": True,
                                    "found": True,
                                    "reason": "Found, was appending, but item already exists",
                                    "key": key,
                                    "search": value,
                                    "value": json.loads(allvalues["value"]),
                                }
                                
                            # Lol    
                            break
                except Exception as e:
                    parsedvalue = [str(parsedvalue)]
                    append = True

                if not append:
                    return {
                        "success": True,
                        "found": False,
                        "reason": "Not found, not appending (2)!",
                        "key": key,
                        "search": value,
                        "value": json.loads(allvalues["value"]),
                    }

                new_value = parsedvalue
                if new_value == None:
                    new_value = [value]

                new_value.append(value)
                data["value"] = json.dumps(new_value)

                set_url = "%s/api/v1/orgs/%s/set_cache" % (self.url, org_id)
                response = requests.post(set_url, json=data, verify=False)
                exception = ""
                try:
                    allvalues = response.json()
                    #return allvalues

                    return {
                        "success": True,
                        "found": False,
                        "reason": "Appended as it didn't exist",
                        "key": key,
                        "search": value,
                        "value": new_value,
                    }
                except Exception as e:
                    exception = e
                    pass

                return {
                    "success": False,
                    "found": True,
                    "reason": f"Failed to set append the value: {exception}. This should never happen",
                    "search": value,
                    "key": key
                }

            #return allvalues

        except Exception as e:
            print("[ERROR] Failed check cache contains: %s" % e)
            return {
                "success": False,
                "key": key,
                "reason": f"Failed to handle cache contains. Is the original value a list?: {e}",
                "search": value,
                "found": False,
            }

        return value.text 

    
    ## Adds value to a subkey of the cache
    ## subkey = "hi", value = "test", overwrite=False
    ## {"subkey": "hi", "value": "test"}
    ## subkey = "hi", value = "test2", overwrite=True
    ## {"subkey": "hi", "value": "test2"}
    ## subkey = "hi", value = "test3", overwrite=False
    ## {"subkey": "hi", "value": ["test2", "test3"]}

    def change_cache_subkey(self, key, subkey, value, overwrite):
        org_id = self.full_execution["workflow"]["execution_org"]["id"]
        url = "%s/api/v1/orgs/%s/set_cache" % (self.url, org_id)

        if isinstance(value, dict) or isinstance(value, list):
            try:
                value = json.dumps(value)
            except Exception as e:
                self.logger.info(f"[WARNING] Error in JSON dumping (set cache): {e}")

        elif not isinstance(value, str):
            value = str(value)

        data = {
            "workflow_id": self.full_execution["workflow"]["id"],
            "execution_id": self.current_execution_id,
            "authorization": self.authorization,
            "org_id": org_id,
            "key": key,
            "value": value,
        }

        response = requests.post(url, json=data, verify=False)
        try:
            allvalues = response.json()
            allvalues["key"] = key
            #allvalues["value"] = json.loads(json.dumps(value))

            if (value.startswith("{") and value.endswith("}")) or (value.startswith("[") and value.endswith("]")):
                try:
                    allvalues["value"] = json.loads(value)
                except json.decoder.JSONDecodeError as e:
                    self.logger.info("[WARNING] Failed inner value cache parsing: %s" % e)
                    allvalues["value"] = str(value)
            else:
                allvalues["value"] = str(value)

            return json.dumps(allvalues)
        except:
            self.logger.info("Value couldn't be parsed")
            return response.text

    def delete_cache_value(self, key):
        return self.delete_cache(key)

    def get_cache_value(self, key):
        org_id = self.full_execution["workflow"]["execution_org"]["id"]
        url = "%s/api/v1/orgs/%s/get_cache" % (self.url, org_id)
        data = {
            "workflow_id": self.full_execution["workflow"]["id"],
            "execution_id": self.current_execution_id,
            "authorization": self.authorization,
            "org_id": org_id,
            "key": key,
        }

        value = requests.post(url, json=data, verify=False)
        try:
            allvalues = value.json()
            allvalues["key"] = key

            if allvalues["success"] == True and len(allvalues["value"]) > 0:
                allvalues["found"] = True
            else:
                allvalues["success"] = True 
                allvalues["found"] = False 

            try:
                parsedvalue = json.loads(allvalues["value"])
                allvalues["value"] = parsedvalue

            except:
                pass

            return json.dumps(allvalues)
        except:
            self.logger.info("Value couldn't be parsed, or json dump of value failed")
            return value.text

    def set_cache_value(self, key, value):
        org_id = self.full_execution["workflow"]["execution_org"]["id"]
        url = "%s/api/v1/orgs/%s/set_cache" % (self.url, org_id)

        if isinstance(value, dict) or isinstance(value, list):
            try:
                value = json.dumps(value)
            except Exception as e:
                self.logger.info(f"[WARNING] Error in JSON dumping (set cache): {e}")
        
        if not isinstance(value, str):
            value = str(value)

        data = {
            "workflow_id": self.full_execution["workflow"]["id"],
            "execution_id": self.current_execution_id,
            "authorization": self.authorization,
            "org_id": org_id,
            "key": key,
            "value": value,
        }

        response = requests.post(url, json=data, verify=False)
        try:
            allvalues = response.json()
            allvalues["key"] = key
            #allvalues["value"] = json.loads(json.dumps(value))

            if (value.startswith("{") and value.endswith("}")) or (value.startswith("[") and value.endswith("]")):
                try:
                    allvalues["value"] = json.loads(value)
                except json.decoder.JSONDecodeError as e:
                    self.logger.info("[WARNING] Failed inner value cache parsing: %s" % e)
                    allvalues["value"] = str(value)
            else:
                allvalues["value"] = str(value)

            return json.dumps(allvalues)
        except:
            self.logger.info("Value couldn't be parsed")
            return response.text

    def convert_json_to_tags(self, json_object, split_value=", ", include_key=True, lowercase=True):
        if isinstance(json_object, str):
            try:
                json_object = json.loads(json_object)
            except json.decoder.JSONDecodeError as e:
                self.logger.info("Failed to parse list2 as json: %s. Type: %s" % (e, type(json_object)))

        if isinstance(lowercase, str) and lowercase.lower() == "true":
            lowercase = True
        else:
            lowercase = False

        if isinstance(include_key, str) or include_key.lower() == "true":
            include_key = True
        else:
            include_key = False

        parsedstring = []
        try:
            for key, value in json_object.items():
                if isinstance(value, str) or isinstance(value, int) or isinstance(value, bool):
                    if include_key == True:
                        parsedstring.append("%s:%s" % (key, value))
                    else:
                        parsedstring.append("%s" % (value))
                else:
                    self.logger.info("Can't handle type %s" % type(value))
        except AttributeError as e:
            return {
                "success": False,
                "reason": "Json Object is not a dictionary",
            }

        fullstring = split_value.join(parsedstring)
        if lowercase == True:
            fullstring = fullstring.lower()

        return fullstring

    def cidr_ip_match(self, ip, networks):

        if isinstance(networks, str):
            try:
                networks = json.loads(networks)
            except json.decoder.JSONDecodeError as e:
                return {
                    "success": False,
                    "reason": "Networks is not a valid list: {}".format(networks),
                }

        try:
            ip_networks = list(map(ipaddress.ip_network, networks))
            ip_address = ipaddress.ip_address(ip, False)
        except ValueError as e:
            return "IP or some networks are not in valid format.\nError: {}".format(e)

        matched_networks = list(filter(lambda net: (ip_address in net), ip_networks))

        result = {}
        result["ip"] = ip
        result['networks'] = list(map(str, matched_networks))
        result['is_contained'] = True if len(result['networks']) > 0 else False

        return json.dumps(result)

    def get_timestamp(self, time_format):
        timestamp = int(time.time())
        if time_format == "unix" or time_format == "epoch":
            pass

        return timestamp

    def get_hash_sum(self, value):
        md5_value = ""
        sha256_value = ""

        try:
            md5_value = hashlib.md5(str(value).encode('utf-8')).hexdigest()
        except Exception as e:
            pass

        try:
            sha256_value = hashlib.sha256(str(value).encode('utf-8')).hexdigest()
        except Exception as e:
            pass

        parsedvalue = {
            "success": True,
            "original_value": value,
            "md5": md5_value,
            "sha256": sha256_value,
        }

        return parsedvalue 

    def run_oauth_request(self, url, jwt):
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }

        data = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=%s" % jwt

        return requests.post(url, data=data, headers=headers, verify=False).text

    # Based on https://google-auth.readthedocs.io/en/master/reference/google.auth.crypt.html
    def get_jwt_from_file(self, file_id, jwt_audience, scopes, complete_request=True):
        allscopes = scopes


        if "," in scopes:
            allscopes = " ".join(scopes.split(","))
     
        # Service account key path
        filedata = self.get_file(file_id)
        if filedata["success"] == False:
            return {
                "success": False,
                "message": f"Failed to get file for ID {file_id}",
            }
    
        data = json.loads(filedata["data"], strict=False)
        #sa_keyfile = ""
        sa_keyfile = data["private_key"]
        sa_email = data["client_email"]
    
        # The audience to target
        audience = jwt_audience
    
        """Generates a signed JSON Web Token using a Google API Service Account or similar."""
        def get_jwt(sa_keyfile,
                     sa_email,
                     audience,
                     allscopes,
                     expiry_length=3600):
        
            now = int(time.time())
            
            # build payload
            payload = {
                # expires after 'expiry_length' seconds.
                # iss must match 'issuer' in the security configuration in your
                # swagger spec (e.g. service account email). It can be any string.
                'iss': sa_email,
                # aud must be either your Endpoints service name, or match the value
                # specified as the 'x-google-audience' in the OpenAPI document.
                'scope': allscopes,
                'aud':  audience,
                "exp": now + expiry_length,
                'iat': now,

                # sub and email should match the service account's email address
                'sub': sa_email,
                'email': sa_email,
            }
            
            # sign with keyfile
            #signer = crypt.RSASigner.from_service_account_file(sa_keyfile)
            signer = crypt.RSASigner.from_string(sa_keyfile)
            jwt_token = jwt.encode(signer, payload)
            return jwt_token
    
    
        signed_jwt = get_jwt(sa_keyfile, sa_email, audience, allscopes)

        if str(complete_request).lower() == "true":
            return self.run_oauth_request(audience, signed_jwt.decode())
        else:
            return {
                "success": True,
                "jwt": signed_jwt.decode(),
            }

    def get_synonyms(self, input_type):
        if input_type == "cases":
            return {
                "id": [
                    "id",
                    "ref",
                    "sourceref",
                    "reference",
                    "sourcereference",
                    "alertid",
                    "caseid",
                    "incidentid",
                    "serviceid",
                    "sid",
                    "uid",
                    "uuid",
                    "teamid",
                    "messageid",
                  ],
                  "title": ["title", "message", "subject", "name"],
                  "description": ["description", "status", "explanation", "story", "details", "snippet"],
                  "email": ["mail", "email", "sender", "receiver", "recipient"],
                  "data": [
                    "data",
                    "ip",
                    "domain",
                    "url",
                    "hash",
                    "md5",
                    "sha2",
                    "sha256",
                    "value",
                    "item",
                    "rules",
                  ],
                  "tags": ["tags", "taxonomies", "labels", "labelids"],
                  "assignment": [
                    "assignment",
                    "user",
                    "assigned_to",
                    "users",
                    "closed_by",
                    "closing_user",
                    "opened_by",
                  ],
                  "severity": [
                    "severity",
                    "sev",
                    "magnitude",
                    "relevance",
                  ]
            }
        
        return []
    
    def find_key(self, inputkey, synonyms):
        inputkey = inputkey.lower().replace(" ", "").replace(".", "")
        for key, value in synonyms.items():
            if inputkey in value:
                return key
    
        return inputkey
    
    def run_key_recursion(self, json_input, synonyms):
        if isinstance(json_input, str) or isinstance(json_input, int) or isinstance(json_input, float):
            return json_input, {}
    
        if isinstance(json_input, list):
            if len(json_input) != 1:
                return json_input, {}
            else:
                json_input = json_input[0]
    
            #new_list = []
            #for item in json_input:
            #run_key_recursion(item, synonyms)
            #new_dict[new_key], found_important = run_key_recursion(value, synonyms)
    
        # Looks for exact key:value stuff in other format
        if len(json_input.keys()) == 2:
            newkey = ""
            newvalue = ""
            for key, value in json_input.items():
                if key == "key" or key == "name":
                    newkey = value
                elif key == "value":
                    newvalue = value
    
            if len(newkey) > 0 and len(newvalue) > 0:
                json_input[newkey] = newvalue
                try:
                    del json_input["name"]
                except:
                    pass
    
                try:
                    del json_input["value"]
                except:
                    pass
    
                try:
                    del json_input["key"]
                except:
                    pass
    
        important_fields = {}
        new_dict = {}
        for key, value in json_input.items():
            new_key = self.find_key(key, synonyms)
    
            if isinstance(value, list):
                new_list = []
                for subitem in value:
                    returndata, found_important = self.run_key_recursion(subitem, synonyms)
    
                    new_list.append(returndata)
                    for subkey, subvalue in found_important.items():
                        important_fields[subkey] = subvalue 
    
                new_dict[new_key] = new_list
    
            elif isinstance(value, dict):
                # FIXMe: Try to understand Key:Values as well by translating them
                # name/key: subject
                # value: This is a subject
                # will become:
                # subject: This is a subject
                    
                new_dict[new_key], found_important = self.run_key_recursion(value, synonyms)
    
                for subkey, subvalue in found_important.items():
                    important_fields[subkey] = subvalue
            else:
                new_dict[new_key] = value
    
            # Translated fields are added as important
            if key.lower().replace(" ", "").replace(".", "") != new_key:
                try:
                    if len(new_dict[new_key]) < str(important_fields[new_key]):
                        important_fields[new_key] = new_dict[new_key]
                except KeyError as e:
                    important_fields[new_key] = new_dict[new_key]
                except:
                    important_fields[new_key] = new_dict[new_key]
    
            #break
    
        return new_dict, important_fields
    
    # Should translate the data to something more useful
    def get_standardized_data(self, json_input, input_type):
        if isinstance(json_input, str):
            json_input = json.loads(json_input, strict=False)
    
        input_synonyms = self.get_synonyms(input_type)
        parsed_data, important_fields = self.run_key_recursion(json_input, input_synonyms)
    
        # Try base64 decoding and such too?
        for key, value in important_fields.items():
            try:
                important_fields[key] = important_fields[key][key]
            except:
                pass
    
            try:
                important_fields[key] = base64.b64decode(important_fields[key])
            except:
                pass
    
        return {
            "success": True,
            "original": json_input,
            "parsed": parsed_data,
            "changed_fields": important_fields,
        }

    def generate_random_string(length=16, special_characters=True):
        try:
            length = int(length)
        except:
            return {
                "success": False,
                "error": "Length needs to be a whole number",
            }

        # get random password pf length 8 with letters, digits, and symbols
        characters = string.ascii_letters + string.digits + string.punctuation
        if str(special_characters).lower() == "false":
            characters = string.ascii_letters + string.digits + string.punctuation

        password = ''.join(random.choice(characters) for i in range(length))

        return {
            "success": True,
            "password": password,
        }
    
    def run_ssh_command(self, host, port, user_name, private_key_file_id, password, command):
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if port:
            port = int(port)
        else:
            port = 22

        if private_key_file_id:
            new_file = self.get_file(private_key_file_id)

            try:
                key_data = new_file["data"].decode()
            except Exception as e:
                return {"success":"false","message":str(e)}

            private_key_file = StringIO()
            private_key_file.write(key_data)
            private_key_file.seek(0)
            private_key = paramiko.RSAKey.from_private_key(private_key_file)
            
            try:
                ssh_client.connect(hostname=host,username=user_name,port=port, pkey= private_key)
            except Exception as e:
                return {"success":"false","message":str(e)}
        else:
            try:
                ssh_client.connect(hostname=host,username=user_name,port=port, password=str(password))
            except Exception as e:
                return {"success":"false","message":str(e)}

        try:
            stdin, stdout, stderr = ssh_client.exec_command(str(command))
        except Exception as e:
            return {"success":"false","message":str(e)}

        return {"success":"true","output": stdout.read().decode(errors='ignore')}

    def parse_ioc(self, input_string, input_type="all"):
        ioc_types = ["domains", "urls", "email_addresses", "ipv4s", "ipv4_cidrs", "md5s", "sha256s", "sha1s", "cves"]

        # Remember overriding ioc types we care about
        if input_type == "" or input_type == "all":
            input_type = "all"
        else:
            input_type = input_type.split(",")
            for i in range(len(input_type)):
                item = input_type[i]

                item = item.strip()
                if not item.endswith("s"):
                    item = "%ss" % item

                input_type[i] = item

            ioc_types = input_type

        iocs = find_iocs(str(input_string), included_ioc_types=ioc_types)
        newarray = []
        for key, value in iocs.items():
            if input_type != "all":
                if key not in input_type:
                    continue

            if len(value) > 0:
                for item in value:
                    # If in here: attack techniques. Shouldn't be 3 levels so no
                    # recursion necessary
                    if isinstance(value, dict):
                        for subkey, subvalue in value.items():
                            if len(subvalue) > 0:
                                for subitem in subvalue:
                                    data = {
                                        "data": subitem,
                                        "data_type": "%s_%s" % (key[:-1], subkey),
                                    }
                                    if data not in newarray:
                                        newarray.append(data)
                    else:
                        data = {"data": item, "data_type": key[:-1]}
                        if data not in newarray:
                            newarray.append(data)

        # Reformatting IP
        for item in newarray:
            if "ip" in item["data_type"]:
                item["data_type"] = "ip"
                try:
                    item["is_private_ip"] = ipaddress.ip_address(item["data"]).is_private
                except:
                    pass

        try:
            newarray = json.dumps(newarray)
        except json.decoder.JSONDecodeError as e:
            return "Failed to parse IOC's: %s" % e

        return newarray
    

    def split_text(self, text):
        # Split text into chunks of 10kb. Add each 10k to array
        # In case e.g. 1.2.3.4 lands exactly on 20k boundary, it may be useful to overlap here.
        # (just shitty code to reduce chance of issues) while still going fast
        arr_one = []
        max_len = 5000 
        current_string = ""
        overlaps = 100 

        for i in range(0, len(text)):
            current_string += text[i]
            if len(current_string) > max_len:
                # Appending just in case even with overlaps
                if len(text) > i+overlaps:
                    current_string += text[i+1:i+overlaps]
                else:
                    current_string += text[i+1:]

                arr_one.append(current_string)
                current_string = ""

        if len(current_string) > 0:
            arr_one.append(current_string)

        return arr_one 

    def _format_result(self, result):
        final_result = {}
        
        for res in result:
            for key,val in res.items():
                if key in final_result:
                    if isinstance(val, list) and len(val) > 0:
                        for i in val:
                            final_result[key].append(i)
                    elif isinstance(val, dict):
                        if key in final_result:
                            if isinstance(val, dict):
                                for k,v in val.items():
                                    val[k].append(v)
                else:
                    final_result[key] = val

        return final_result

    # See function for how it works~: parse_ioc_new(..)
    def _with_concurency(self, array_of_strings, ioc_types):
        results = []
        #start = time.perf_counter()

        # Workers dont matter..?
        # What can we use instead? 

        workers = 4
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            # Submit the find_iocs function for each string in the array
            futures = [executor.submit(
                find_iocs, 
                text=string, 
                included_ioc_types=ioc_types,
            ) for string in array_of_strings]

            # Wait for all tasks to complete
            concurrent.futures.wait(futures)

            # Retrieve the results if needed
            results = [future.result() for future in futures]
        
        return self._format_result(results)

    # FIXME: Make this good and actually faster than normal
    # For now: Concurrency doesn't make it faster due to GIL in python.
    # May need to offload this to an executable or something 
    def parse_ioc_new(self, input_string, input_type="all"):
        if input_type == "":
            input_type = "all"

        ioc_types = ["domains", "urls", "email_addresses", "ipv4s", "ipv4_cidrs", "md5s", "sha256s", "sha1s", "cves"]

        if input_type == "" or input_type == "all":
            ioc_types = ioc_types
        else:
            input_type = input_type.split(",")
            for item in input_type:
                item = item.strip()

            ioc_types = input_type

        input_string = str(input_string)

        if len(input_string) > 10000:
            iocs = self._with_concurency(self.split_text(input_string), ioc_types=ioc_types)
        else:
            iocs = find_iocs(input_string, included_ioc_types=ioc_types)

        newarray = []
        for key, value in iocs.items():
            if input_type != "all":
                if key not in input_type:
                    continue
    
            if len(value) == 0:
                continue

            for item in value:
                # If in here: attack techniques. Shouldn't be 3 levels so no
                # recursion necessary
                if isinstance(value, dict):
                    for subkey, subvalue in value.items():
                        if len(subvalue) == 0:
                            continue

                        for subitem in subvalue:
                            data = {
                                "data": subitem,
                                "data_type": "%s_%s" % (key[:-1], subkey),
                            }

                            if data not in newarray:
                                newarray.append(data)
                else:
                    data = {"data": item, "data_type": key[:-1]}
                    if data not in newarray:
                        newarray.append(data)

        # Reformatting IP
        i = -1
        for item in newarray:
            i += 1
            if "ip" not in item["data_type"]:
                continue

            newarray[i]["data_type"] = "ip"
            try:
                newarray[i]["is_private_ip"] = ipaddress.ip_address(item["data"]).is_private
            except Exception as e:
                pass

        try:
            newarray = json.dumps(newarray)
        except json.decoder.JSONDecodeError as e:
            return "Failed to parse IOC's: %s" % e

        return newarray

    def merge_incoming_branches(self, input_type="list"):
        wf = self.full_execution["workflow"]
        if "branches" not in wf or not wf["branches"]:
            return {
                "success": False,
                "reason": "No branches found"
            }

        if "results" not in self.full_execution or not self.full_execution["results"]:
            return {
                "success": False,
                "reason": "No results for previous actions not found"
            }

        if not input_type:
            input_type = "list"

        branches = wf["branches"]
        cur_action = self.action
        #print("Found %d branches" % len(branches))

        results = []
        for branch in branches:
            if branch["destination_id"] != cur_action["id"]:
                continue

            # Find result for the source
            source_id = branch["source_id"]

            for res in self.full_execution["results"]:
                if res["action"]["id"] != source_id:
                    continue

                try:
                    parsed = json.loads(res["result"])
                    results.append(parsed)
                except Exception as e:
                    results.append(res["result"])

                break

        if input_type == "list":
            newlist = []
            for item in results:
                if not isinstance(item, list):
                    continue

                for subitem in item:
                    if subitem in newlist:
                        continue

                    newlist.append(subitem)
                #newlist.append(item)

            results = newlist
        elif input_type == "dict":
            new_dict = {}
            for item in results:
                if not isinstance(item, dict): 
                    continue

                new_dict = self.merge_lists(new_dict, item)

            results = json.dumps(new_dict)
        else:
            return {
                "success": False,
                "reason": "No results from source branches with type %s" % input_type
            }

        return results

    def list_cidr_ips(self, cidr):
        defaultreturn = {
            "success": False,
            "reason": "Invalid CIDR address"
        }

        if not cidr:
            return defaultreturn

        if "/" not in cidr:
            defaultreturn["reason"] = "CIDR address must contain / (e.g. /12)"
            return defaultreturn

        try:
            cidrnumber = int(cidr.split("/")[1])
        except ValueError as e:
            defaultreturn["exception"] = str(e)
            return defaultreturn

        if cidrnumber < 12:
            defaultreturn["reason"] = "CIDR address too large. Please stay above /12"
            return defaultreturn

        try:
            net = ipaddress.ip_network(cidr)
        except ValueError as e:
            defaultreturn["exception"] = str(e)
            return defaultreturn

        ips = [str(ip) for ip in net]
        returnvalue = {
            "success": True,
            "amount": len(ips),
            "ips": ips
        }

        return returnvalue
    

# Run the actual thing after we've checked params
def run(request):
	try:
		action = request.get_json(force=True)
	except:
		return f'Error parsing JSON'

	if action == None:
		return f'No JSON detected'

	#authorization_key = action.get("authorization")
	#current_execution_id = action.get("execution_id")
	
	if action and "name" in action and "app_name" in action:
		Tools.run(action=action)
		return f'Attempting to execute function {action["name"]} in app {action["app_name"]}' 

	return f'Action ran!'

	