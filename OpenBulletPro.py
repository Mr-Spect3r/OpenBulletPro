try:

    from enum import Enum
    import re,json,base64
    from jsonpath_ng import parse as JTParse
    from bs4 import BeautifulSoup
    from shutil import copyfile, move, rmtree
    from random import choice, shuffle,randint
    from urllib.parse import quote, unquote
    from datetime import datetime,timezone
    import random
    import time
    import math
    from html import escape, unescape
    import hashlib
    from hashlib import pbkdf2_hmac
    import hmac
    from secrets import token_bytes
    import requests
    from requests.cookies import RequestsCookieJar
    from requests import Request, Session
    from requests.auth import HTTPBasicAuth
    from requests.utils import quote
    import warnings
    from math import floor
    from typing import Union
    import os
    import argparse
    import urllib3
    from functools import lru_cache
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import threading
    from colorama import init

except Exception as F:
    exit(f"Module Error {F}\n\nTo install the module, enter the following command: pip install {F}")

rd, gn, lgn, yw, lrd, be, pe = '\033[00;31m', '\033[00;32m', '\033[01;32m', '\033[01;33m', '\033[01;31m', '\033[00;34m', '\033[01;35m'
cn, k,g = '\033[00;36m', '\033[90m','\033[38;5;130m'

def clear():
    os.system('cls || clear')	

init()
	
class TF:
    SUCCESS = '\033[01;32mSUCCESS '
    ERROR = '\033[00;31mERROR '
    NONE = '\033[90mNONE '
    FAIL = '\033[00;31mFAIL '
    BAN = '\033[01;31mBAN '
    RETRY = '\033[01;33mRETRY '
    CUSTOM = '\033[00;36mCUSTOM '

COMPARER_FUNCTIONS = {
    "EqualTo": lambda L, R: any(str(l) == str(R) for l in L),
    "NotEqualTo": lambda L, R: any(str(l) != str(R) for l in L),
    "GreaterThan": lambda L, R: any(float(str(l).replace(",", ".")) > float(str(R).replace(",", ".")) for l in L),
    "LessThan": lambda L, R: any(float(str(l).replace(",", ".")) < float(str(R).replace(",", ".")) for l in L),
    "Contains": lambda L, R: any(str(R) in str(l) for l in L),
    "DoesNotContain": lambda L, R: all(str(R) not in str(l) for l in L),
    "Exists": lambda L, R: len(L) > 0 and any(str(l) != "" for l in L),
    "DoesNotExist": lambda L, R: len(L) == 0 or all(str(l) == "" for l in L),
    "MatchesRegex": lambda L, R: any(re.search(str(R), str(l)) for l in L),
    "DoesNotMatchRegex": lambda L, R: all(not re.search(str(R), str(l)) for l in L),
}

@lru_cache(maxsize=128)
def get_compiled_regex(pattern):
    return re.compile(pattern)

def ToSleep(text,Time):
    for char in text:
        print(char, end='', flush=True)
        time.sleep(Time)

class CVV:
    def __init__(self, Name:str, Value,IsCapture:bool,Hidden=False):

        if type(Value) == list:
            self.var_type = VARLB.List
        elif type(Value) == str:
            self.var_type = VARLB.Single
        elif type(Value) == dict:
            self.var_type = VARLB.Dictionary

        self.Name = Name
        self.Value = Value
        self.IsCapture = IsCapture
        self.Hidden = Hidden
    
    def ToString(self):
        if self.var_type == VARLB.Single:
            return self.Value
        elif self.var_type == VARLB.List:
            if type(self.Value == list): return "[" + ",".join(self.Value) + "]"
            else: return ""
        elif self.var_type == VARLB.Dictionary:
            return "{" + ",".join(["(" + v[0] + ", " + v[1] + ")" for v in self.Value.items()]) + "}"
    
    def GetListItem(self,index):
        if self.var_type != VARLB.List: return None

        List = list(self.Value)

        if index < 0:
            index = len(List) + index    
        
        if index > len(List) - 1 or index < 0: return None
        return List[index]

    def GetDictValue(self,key):
        Dict = self.Value
        Dict = next((v for v in self.Value.items() if v[0] == key),None)
        if Dict:
            return Dict[1]
        else:
            print("Key not in dictionary")
            return None

    def GetDictKey(self,value):
        Dict = self.Value
        Dict = next((v for v in self.Value.items() if v[1] == value),None)
        if Dict:
            return Dict[0]
        else:
            print("Value not in dictionary")
            return None

class VariableList:
    def __init__(self):
        self.all = []
    def Captures(self):
        return [v for v in self.all if v.IsCapture == True and v.Hidden == False]
    def VariableList(self):
        self.all = []
    def VariableListWithList(self,List):
        self.all = List
    def GetWithName(self,name):
        return next((v for v in self.all if v.Name == name),None)
    def GetWithNameAndType(self,name,var_type):
        return next((v for v in self.all if v.var_type == var_type and v.Name == name),None)
        
    def GetSingle(self,name):
        return self.GetWithNameAndType(name,VARLB.Single).Value
    def GetList(self,name):
        v = self.GetWithNameAndType(name,VARLB.List)
        if v:
            return v.Value
        else:
            return None
    def GetDictionary(self,name):
        return self.GetWithNameAndType(name,VARLB.Dictionary)
    def VariableExists(self,name):
        return any([v for v in self.all if v.Name == name])
    def VariableExistsWithType(self,name, var_type):
        return any([v for v in self.all if v.Name == name and v.var_type == var_type])
    def Set(self,variable:CVV):
        self.Remove(variable.Name)
        self.all.append(variable)
    def SetNew(self, variable):
        if self.VariableExists(variable.Name) == False: self.Set(variable)
    def Remove(self,name):
        self.all = [v for v in self.all if v.Name != name]
    def ToCaptureString(self):
        return " | ".join([v.Name + "=" + v.ToString() for v in self.Captures()]) 
    
class VARLB:
    Single = "Single"
    List = "List"
    Dictionary = "Dictionary"
        

class proxyType(str,Enum):
    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"
class BotData:
    class BotStatus(str,Enum):
        NONE = "NONE"
        ERROR = "ERROR"
        SUCCESS = "SUCCESS"
        FAIL = "FAIL"
        BAN = "BAN"
        RETRY = "RETRY"
        CUSTOM = "CUSTOM"
    def __init__(self,status=BotStatus.NONE, proxy:dict = None):
        self.Variables = VariableList()
        self.status = status
        self.cwd = None
        self.proxy = proxy

    def ResponseSourceGet(self):
        return self.Variables.GetWithName("SOURCE").Value
    def ResponseSourceSet(self,variable):
        self.Variables.Set(variable)

    def AddressGet(self):
        return self.Variables.GetWithName("ADDRESS").Value
    def AddressSet(self,variable):
        self.Variables.Set(variable)

    def ResponseCodeGet(self):
        return self.Variables.GetWithName("RESPONSECODE").Value
    def ResponseCodeSet(self,variable):
        self.Variables.Set(variable)

    def ResponseHeadersGet(self):
        return self.Variables.GetWithName("HEADERS").Value
    def ResponseHeadersSet(self,variable):
        self.Variables.Set(variable)

    def CookiesGet(self):
        return self.Variables.GetWithName("COOKIES")
    def CookiesSet(self,variable):
        self.Variables.Set(variable)

def ParseArguments(input_string, delimL, delimR):
    output = []
    pattern = "\\" + delimL + "([^\\" + delimR + "]*)\\" + delimR
    matches = re.findall(pattern, input_string)
    for match in matches:
        output.append(match)
    return output

def ReplaceValues(input_string, BotData):
    if input_string is None: 
        return input_string
    if "<" not in input_string or ">" not in input_string: 
        return input_string

    output = input_string
    max_iterations = 10  
    iteration = 0
    
    while "<" in output and ">" in output and iteration < max_iterations:
        iteration += 1
        previous = output

        r = get_compiled_regex('<([^<>]*)>')
        matches = r.findall(output)
        
        if not matches:
            break
            
        for match in matches:
            full = "<" + match + ">"

            name_match = re.search('^[^\[\{\(]*', match)
            if not name_match:
                continue
                
            name = name_match.group(0)
            v = BotData.Variables.GetWithName(name)
            
            if not v:
                continue
                
            args = match.replace(name, "")
            
            if v.var_type == VARLB.Single:
                output = output.replace(full, str(v.Value))
                
            elif v.var_type == VARLB.List:
                if not args: 
                    output = output.replace(full, v.ToString())
                elif "[" in args and "]" in args:
                    try:
                        index = int(re.search(r'\[(\d+)\]', args).group(1))
                        item = v.GetListItem(index)
                        if item is not None:
                            output = output.replace(full, str(item))
                    except:
                        pass
                        
            elif v.var_type == VARLB.Dictionary:
                if "(" in args and ")" in args:
                    try:
                        dicKey = re.search(r'\((.*?)\)', args).group(1)
                        value = v.GetDictValue(dicKey)
                        if value:
                            output = output.replace(full, str(value))
                    except:
                        pass
                elif "{" in args and "}" in args:
                    try:
                        dicVal = re.search(r'\{(.*?)\}', args).group(1)
                        key = v.GetDictKey(dicVal)
                        if key:
                            output = output.replace(full, str(key))
                    except:
                        pass
                else:
                    output = output.replace(full, v.ToString())
        
        if output == previous:
            break
    
    return output


def ReplaceValuesRecursive(input_string,BotData):


    toReplace = []
    r = re.compile('<([^\\[]*)\\[\\*\\]>')
    matches = r.findall(input_string)

    variables = []


    for m in matches:
        name = m

        variable = BotData.Variables.GetWithName(name)
        if variable:
            if variable.var_type == VARLB.List: variables.append(variable)
        
            
    def theEnd(toReplace,BotData):
        toReplace = [ReplaceValues(replace,BotData) for replace in toReplace]
        return toReplace

    if len(variables) > 0:
        max_index = len(variable.Value)
        i = 0

        while i < max_index:
            replaced = input_string

            for variable in variables:
                variable_Name = variable.Name
                theList = variable.Value
                if len(theList) > i:
                    replaced = replaced.replace(f"<{variable_Name}[*]>", str(theList[i]))
                else:
                    replaced = replaced.replace(f"<{variable_Name}[*]>", "NULL")

            toReplace.append(replaced)
            i += 1
        return theEnd(toReplace,BotData)


    r = re.compile("<([^\\(]*)\\(\\*\\)>")
    match = r.match(input_string)

    if match:
        full = match.group(0)
        name = match.group(1)

        theDict = BotData.Variables.GetDictionary(name)

        if not theDict: toReplace.append(input_string)
        else:
            theDict = theDict.Value
            for key in theDict:
                aDict = {key,theDict[key]}
                toReplace.append(input_string.replace(full,str(aDict)))
        return theEnd(toReplace,BotData)
    
    r = re.compile("<([^\\{]*)\\{\\*\\}>")
    match = r.match(input_string)

    if match:
        full = match.group(0)
        name = match.group(1)

        theDict = BotData.Variables.GetWithName(name)

        if not theDict: toReplace.append(input_string)
        else:
            theDict = theDict.Value
            for key in theDict:
                toReplace.append(input_string.replace(full,str(key)))
        return theEnd(toReplace,BotData)
    toReplace.append(input_string)
    return theEnd(toReplace,BotData)

def InsertVariable(BotData,isCapture,recursive,values,variableName,prefix="" ,suffix="" ,urlEncode=False ,createEmpty=True):

    thisList = values
    if urlEncode == False: pass

    variable = None

    if recursive:
        if len(thisList) == 0:
            if createEmpty:
                variable = CVV(variableName,thisList,isCapture)
        else:
            variable = CVV(variableName,thisList,isCapture)
    else:
        if len(thisList) == 0:
            if createEmpty:
                variable = CVV(variableName,"",isCapture)
        else:
            variable = CVV(variableName,thisList[0],isCapture)
    if variable:
        BotData.Variables.Set(variable)
    return True

class Comparer(str,Enum):
    LessThan = "LessThan"
    GreaterThan = "GreaterThan"
    EqualTo = "EqualTo"
    NotEqualTo = "NotEqualTo"
    Contains = "Contains"
    DoesNotContain = "DoesNotContain"
    Exists = "Exists"
    DoesNotExist = "DoesNotExist"
    MatchesRegex = "MatchesRegex"
    DoesNotMatchRegex = "DoesNotMatchRegex"


class Comparer(str,Enum):
    LessThan = "LessThan"
    GreaterThan = "GreaterThan"
    EqualTo = "EqualTo"
    NotEqualTo = "NotEqualTo"
    Contains = "Contains"
    DoesNotContain = "DoesNotContain"
    Exists = "Exists"
    DoesNotExist = "DoesNotExist"
    MatchesRegex = "MatchesRegex"
    DoesNotMatchRegex = "DoesNotMatchRegex"

def Verify(Left, comparer, Right):
    # تبدیل Left به لیست اگر نیست
    if not isinstance(Left, list):
        L = [Left]
    else:
        L = Left
    
    R = Right

    if isinstance(comparer, Comparer):
        comparer_name = comparer.value
    else:
        comparer_name = str(comparer)

    func = COMPARER_FUNCTIONS.get(comparer_name)
    if func is None:
        print(f"Warning: Unknown comparer {comparer_name}")
        return False
    
    try:
        return func(L, R)
    except Exception as e:
        print(f"Error in Verify: {e}")
        return False

def ReplaceAndVerify(Left, comparer, Right, BotData):

    L_result = ReplaceValuesRecursive(Left, BotData)
    R = ReplaceValues(Right, BotData)

    if not isinstance(L_result, list):
        L = [L_result]
    else:
        L = L_result

    if isinstance(comparer, Comparer):
        comparer_name = comparer.value
    else:
        comparer_name = str(comparer)

    func = COMPARER_FUNCTIONS.get(comparer_name)
    if func is None:
        print(f"Warning: Unknown comparer {comparer_name}")
        return False
    
    try:
        return func(L, R)
    except Exception as e:
        print(f"Error in ReplaceAndVerify: {e}")
        return False

class Key:
    def __init__(self,LeftTerm="",Comparer="",RightTerm=""):
        self.LeftTerm = LeftTerm
        self.Comparer = Comparer
        self.RightTerm = RightTerm

    def CheckKey(self,BotData):
        try:
            return ReplaceAndVerify(self.LeftTerm,self.Comparer,self.RightTerm,BotData)
        except Exception:
            return False
        
class KeychainType(Enum):
    Success = "Success"
    Failure = "Failure"
    Ban = "Ban"
    Retry = "Retry"
    Custom = "Custom"

class KeychainMode(Enum):
    OR = "OR"
    AND = "AND"
class KeyChain:
    def __init__(self,Type=None,Mode=None,banOn4XX=None,banOnToCheck=None,Keys=None):
        self.Type = KeychainType.Success
        self.Mode = KeychainMode.AND
        self.Keys = []

    def CheckKeys(self,BotData):
        if self.Mode == KeychainMode.OR:
            for key in self.Keys:
                if key.CheckKey(BotData):
                    return True
            return False
        elif self.Mode == KeychainMode.AND:
            for key in self.Keys:
                if not key.CheckKey(BotData):
                    return False
            return True

class Key:
    def __init__(self,LeftTerm="",Comparer="",RightTerm=""):
        self.LeftTerm = LeftTerm
        self.Comparer = Comparer
        self.RightTerm = RightTerm

    def CheckKey(self,BotData):
        try:
            return ReplaceAndVerify(self.LeftTerm,self.Comparer,self.RightTerm,BotData)
        except Exception:
            return False
        
class KeychainType(Enum):
    Success = "Success"
    Failure = "Failure"
    Ban = "Ban"
    Retry = "Retry"
    Custom = "Custom"

class KeychainMode(Enum):
    OR = "OR"
    AND = "AND"
class KeyChain:
    def __init__(self,Type=None,Mode=None,banOn4XX=None,banOnToCheck=None,Keys=None):
        self.Type = KeychainType.Success
        self.Mode = KeychainMode.AND
        self.Keys = []

    def CheckKeys(self,BotData):
        if self.Mode == KeychainMode.OR:
            for key in self.Keys:
                if key.CheckKey(BotData):
                    return True
            return False
        elif self.Mode == KeychainMode.AND:
            for key in self.Keys:
                if not key.CheckKey(BotData):
                    return False
            return True

import re

class LineParser:
    def __init__(self) -> None:
        self.current = ""


def GetPattern(TokenType):
    tokens = {"Label":'^#[^ ]*',
              "Parameter":'^[^ ]*',
              "Literal":'\"(\\\\.|[^\\\"])*\"',
              "Arrow":'->'}
    return tokens.get(TokenType)


def ParseToken(line:LineParser,TokenType,essential,proceed):
    pattern = GetPattern(TokenType)
    token = ""
    r = re.compile(pattern)
    m = r.match(line.current)
    if m:
        token = m.group(0)
        if proceed:
            line.current = line.current[len(token):].strip()
        if TokenType == "Literal":
            token = token[1:len(token) - 1].replace("\\\\", "\\").replace("\\\"", "\"")
    else:
        if essential:
            pass
    return token

def ParseLabel(line:LineParser) -> str:
    return ParseToken(line,"Label",True,True)

def ParseLiteral(line:LineParser) -> str:
    return ParseToken(line,"Literal",True,True)

def ParseEnum(line:LineParser) -> str:
    return ParseToken(line,"Parameter",True,True)

def ParseInt(line:LineParser) -> int:
    try:
        return int(ParseToken(line,"Parameter",True,True))
    except Exception:
        print("Expected Integer value")
        return 0

def Lookahead(line:LineParser):
    token = ParseToken(line,"Parameter",True,False)
    if '\"' in token:
        return "Literal"
    elif '->' in token:
        return "Arrow"
    elif token.startswith("#"):
        return "Label"
    elif "=TRUE" in token.upper() or "=FALSE" in token.upper():
        return "Boolean"
    elif token.isdigit():
        return "Integer"
    else:
        return "Parameter"

def SetBool(line:LineParser,object):
    name, value  = ParseToken(line,"Parameter",True,True).split("=")
    if "TRUE" in value.upper():
        setattr(object,name,True)
    elif "FALSE" in value.upper():
        setattr(object,name,False)
    return name, value

def EnsureIdentifier(line:LineParser, id_string):
    token = ParseToken(line,"Parameter",True,True)
    if token.upper() != id_string.upper():
        print(f"Expected identifier '{id_string}")

def CheckIdentifier(line:LineParser, id_string):
    try:
        token = ParseToken(line,"Parameter",True,False)
        return token.upper() == id_string.upper()
    except Exception:
        return False
    
def ParseArguments(input_string, delimL, delimR):
    output = []
    pattern = "\\" + delimL + "([^\\" + delimR + "]*)\\" + delimR
    matches = re.findall(pattern, input_string)
    for match in matches:
        output.append(match)
    return output

def ReplaceValues(input_string,BotData):
    if input_string == None: return input_string
    if "<" not in input_string and ">" not in input_string: return input_string

    previous = ""
    output = input_string
    args = None
    while "<" in output and ">" in output and output != previous:
        previous = output
        r = re.compile('<([^<>]*)>')
        full = ""
        m = ""
        matches = r.findall(output)

        for match in matches:

            full = "<" + match + ">"
            m = match
            r = re.compile('^[^\\[\\{\\(]*')
            name = r.search(m).group(0)
            v = BotData.Variables.GetWithName(name)
            if not v: return output
            args = m.replace(name,"")           
            if v.var_type == VARLB.Single:
                output = output.replace(full, v.Value)

            elif v.var_type == VARLB.List:
                if not args: 
                    output = output.replace(full,v.ToString())

                elif "[" in args and "]" in args:
                    index = 0
                    try:
                        index = int(ParseArguments(args, "[", "]")[0])
                        item = v.GetListItem(index)
                        if item:
                            output = output.replace(full,item)
                    except Exception:
                        pass

            elif v.var_type == VARLB.Dictionary:

                if "(" in args and ")" in args:
                    dicKey = ParseArguments(args, "(", ")")[0]
                    output = output.replace(full, v.GetDictValue(dicKey))

                elif "{" in args and "}" in args:
                    dicVal = ParseArguments(args, "{", "}")[0]
                    output = output.replace(full, v.GetDictKey(dicVal))

                else: 
                    output = output.replace(full,v.ToString())
        
    return output

def ReplaceValuesRecursive(input_string,BotData):


    toReplace = []
    r = re.compile('<([^\\[]*)\\[\\*\\]>')
    matches = r.findall(input_string)

    variables = []
    for m in matches:
        name = m

        variable = BotData.Variables.GetWithName(name)
        if variable:
            if variable.var_type == VARLB.List: variables.append(variable)
          
    def theEnd(toReplace,BotData):
        toReplace = [ReplaceValues(replace,BotData) for replace in toReplace]
        return toReplace

    if len(variables) > 0:
        max_index = len(variable.Value)
        i = 0

        while i < max_index:
            replaced = input_string

            for variable in variables:
                variable_Name = variable.Name
                theList = variable.Value
                if len(theList) > i:
                    replaced = replaced.replace(f"<{variable_Name}[*]>", str(theList[i]))
                else:
                    replaced = replaced.replace(f"<{variable_Name}[*]>", "NULL")

            toReplace.append(replaced)
            i += 1
        return theEnd(toReplace,BotData)

    r = re.compile("<([^\\(]*)\\(\\*\\)>")
    match = r.match(input_string)

    if match:
        full = match.group(0)
        name = match.group(1)

        theDict = BotData.Variables.GetDictionary(name)

        if not theDict: toReplace.append(input_string)
        else:
            theDict = theDict.Value
            for key in theDict:
                aDict = {key,theDict[key]}
                toReplace.append(input_string.replace(full,str(aDict)))
        return theEnd(toReplace,BotData)
    
    r = re.compile("<([^\\{]*)\\{\\*\\}>")
    match = r.match(input_string)

    if match:
        full = match.group(0)
        name = match.group(1)

        theDict = BotData.Variables.GetWithName(name)

        if not theDict: toReplace.append(input_string)
        else:
            theDict = theDict.Value
            for key in theDict:
                toReplace.append(input_string.replace(full,str(key)))
        return theEnd(toReplace,BotData)
    toReplace.append(input_string)
    return theEnd(toReplace,BotData)

def InsertVariable(BotData,isCapture,recursive,values,variableName,prefix="" ,suffix="" ,urlEncode=False ,createEmpty=True):
    thisList = values
    if urlEncode == False: pass

    variable = None

    if recursive:
        if len(thisList) == 0:
            if createEmpty:
                variable = CVV(variableName,thisList,isCapture)
        else:
            variable = CVV(variableName,thisList,isCapture)
    else:
        if len(thisList) == 0:
            if createEmpty:
                variable = CVV(variableName,"",isCapture)
        else:
            variable = CVV(variableName,thisList[0],isCapture)
    if variable:
        BotData.Variables.Set(variable)
    return True

def LR(input_string, left, right,recursive=False,useRegex=False):
    if not left and not right:
        return [input_string]

    if not left and left in input_string or not right and right in input_string:
        return [input_string]
    
    partial = input_string
    pFrom = 0
    pFrom = 0 
    List = []

    if recursive:
        if useRegex:
            pattern = re.compile(BuildLRPattern(left,right))
            mc = re.findall(pattern,input_string)
            for m in mc:
                List.append(m)
        else:
            while left in partial and right in partial:
                pFrom = (int(partial.find(left)) + int(len(str(left))))
                partial = partial[pFrom:]
                pTo = int(partial.find(right))
                parsed = partial[0:int(pTo)]

                List.append(parsed)
                partial = partial[len(parsed) + len(right):]
                
    else:
        if useRegex:
            pattern = re.compile(BuildLRPattern(left,right))
            mc = re.findall(pattern,input_string)
            if len(mc) > 0: List.append(mc[0])
        else:
            pFrom = (int(partial.find(left)) + int(len(str(left))))
            partial = partial[pFrom:]
            pTo = int(partial.find(right))
            parsed = partial[0:int(pTo)]
            List.append(parsed)
    return List

def JSON(input_string:str,field:str,recursive:bool,useJToken:bool):
    listArray = []
    if useJToken:

        if recursive:

            jsonpath_expr = JTParse(field)
            jsonList = [match.value for match in jsonpath_expr.find(json.loads(input_string))]
            for j in jsonList:
                listArray.append(str(j))
        else:
            jsonList = json.loads(input_string)
            try:
                listArray.append(str(jsonList[field]))
            except Exception:
                listArray.append("")
    else:
        jsonlist = []
        dictList = parseJSON("", input_string, jsonlist)
        for j in dictList:
            if j.get(field) != None:
                value = j.get(field)
                if value.startswith('"'):
                    listArray.append(value[1:len(value) - 1])
                else:
                    listArray.append(value)

        if not recursive and len(listArray) > 1: listArray = [listArray[0]]
    return listArray

def parseJSON(a,b,jsonlist:list):
    jsonlist.append({a:b})

    if b.startswith("["):
        array = []
        try:
            array = json.loads(b)
        except Exception:
            return
        for x in array:
            parseJSON("",json.dumps(x),jsonlist)
    elif b.startswith("{"):
        obj = None
        try:
            obj = json.loads(b)
        except Exception:
            return
        for key,value in obj.items():
            parseJSON(key,json.dumps(value),jsonlist)
    return jsonlist

def REGEX(inputString:str, pattern:str, output:str, recursive=False):
    List = []
    if recursive:
        r = re.compile(pattern)
        mers = r.finditer(inputString)
        for m in mers:
            final = output
            i = 0
            while 1:
                try:
                    final = final.replace("[" + str(i) + "]", str(m[i]))
                except Exception:
                    break
                i += 1
            List.append(final)
    else:
        r = re.compile(pattern)
        m = r.search(inputString)
        final = output
        i = 0
        while 1:
            try:
                final = final.replace("[" + str(i) + "]", str(m[i]))
            except Exception:
                break
            i += 1
        List.append(final)

    return List

def BuildLRPattern(ls,rs):
    left = ls
    right = rs
    if not ls: left = "^"
    if not rs: right = "$"

    return "(?<=" + left + ").+?(?=" + right + ")"

def CSS(input:str, selector:str, attribute:str, index:int = 0, recusive:bool = False):
    
    soup = BeautifulSoup(input, 'html.parser')
    output = []
    if recusive:
        for element in soup.select(selector):
            if attribute == "innerHTML":
                output.append(element.decode_contents())
            elif attribute == "outerHTML":
                output.append(element)
            else:
                attributes = element.attrs
                if attributes.get(attribute):
                    output.append(attributes.get(attribute))

    else:
        if attribute == "innerHTML":
            output.append(soup.select(selector)[index].decode_contents())
        elif attribute == "outerHTML":
            output.append(soup.select(selector)[index])
        else:
            attributes = soup.select(selector)[index].attrs
            if attributes.get(attribute):
                output.append(attributes.get(attribute))
        
    return output

class ParseType(str, Enum):
    LR = "LR"
    CSS = "CSS"
    JSON = "JSON"
    REGEX = "REGEX"
class BlockParse:
    def __init__(self):
        self.VariableName  = ""  
        self.IsCapture  = False 
        self.ParseTarget = "" 
        self.Prefix = ""
        self.Suffix = ""
        self.Recursive = False
        self.DotMatches = False
        self.CaseSensitive  = True
        self.EncodeOutput = False
        self.CreateEmpty = True
        self.ParseType = ""
        self.LeftString = ""
        self.RightString = ""
        self.UseRegexLR = False
        self.CssSelector = ""
        self.AttributeName = ""
        self.CssElementIndex = 0
        self.JsonField = ""
        self.JTokenParsing = False
        self.RegexString = ""
        self.RegexOutput = ""
        self.Dict = None

    def FromLS(self, line:LineParser):

        if str(line.current).startswith("!"):
            return None

        self.Dict = {}

        ParseTarget = ParseLiteral(line)
        self.Dict["ParseTarget"] = ParseTarget
        self.ParseTarget = ParseTarget

        parse_type = ParseEnum(line)
        self.Dict["parse_type"] = parse_type
        self.ParseType = parse_type

        if parse_type == ParseType.REGEX:
            regex_pattern  = ParseLiteral(line)
            self.Dict["regex_pattern"] = regex_pattern
            self.RegexString = regex_pattern

            regex_output = ParseLiteral(line)
            self.Dict["regex_output"] = regex_output
            self.RegexOutput = regex_output

            self.Dict["Booleans"] = {}
            while Lookahead(line) == "Boolean":
                boolean_name, boolean_value = SetBool(line,self)
                self.Dict["Booleans"][boolean_name] = boolean_value
        
        elif parse_type == ParseType.CSS:
            CssSelector =  ParseLiteral(line)
            self.CssSelector = CssSelector
            self.Dict["CssSelector"] = CssSelector

            AttributeName = ParseLiteral(line)
            self.AttributeName = AttributeName
            self.Dict["AttributeName"] = AttributeName

            if Lookahead(line) == "Boolean":
                SetBool(line,self)
            elif Lookahead(line) == "Integer":
                CssElementIndex = ParseInt(line)
                self.CssElementIndex = CssElementIndex
                self.Dict["CssElementIndex"] = CssElementIndex
            self.Dict["Booleans"] = {}
            while Lookahead(line) == "Boolean":
                boolean_name, boolean_value = SetBool(line,self)
                self.Dict["Booleans"][boolean_name] = boolean_value

        elif parse_type == ParseType.JSON:
            JsonField = ParseLiteral(line)
            self.Dict["JsonField"] = JsonField
            self.JsonField = JsonField
            self.Dict["Booleans"] = {}
            while Lookahead(line) == "Boolean":
                boolean_name, boolean_value = SetBool(line,self)
                self.Dict["Booleans"][boolean_name] = boolean_value
                
        elif parse_type == ParseType.LR:
            LeftString = ParseLiteral(line)
            self.Dict["LeftString"] = LeftString
            self.LeftString = LeftString
            RightString = ParseLiteral(line)
            self.RightString = RightString
            self.Dict["RightString"] = RightString
            self.Dict["Booleans"] = {}
            while Lookahead(line) == "Boolean":
                boolean_name, boolean_value = SetBool(line,self)
                self.Dict["Booleans"][boolean_name] = boolean_value

        else:
            return None

        arrow = ParseToken(line,"Arrow",True,True)

        var_type = ParseToken(line,"Parameter",True,True)

        IsCapture = False
        if str(var_type.upper()) == "VAR" or str(var_type.upper()) == "CAP":
            if str(var_type.upper()) == "CAP": IsCapture = True
        self.Dict["IsCapture"] = IsCapture
        self.IsCapture = IsCapture
        
        variable_name = ParseLiteral(line)
        self.Dict["variable_name"] = variable_name
        self.VariableName = variable_name

        prefix = ParseLiteral(line)
        self.Dict["prefix"] = prefix
        self.Prefix = prefix

        suffix = ParseLiteral(line)
        self.Dict["suffix"] = suffix
        self.Suffix = suffix

    def Process(self,BotData):
        original = ReplaceValues(self.ParseTarget,BotData)
        List = []
        if self.ParseType == ParseType.LR:
            List = LR(original,ReplaceValues(self.LeftString,BotData),ReplaceValues(self.RightString,BotData),self.Recursive,self.UseRegexLR)
            print(f"Parsed LR {List} From {original[0:10]}......")
        elif self.ParseType == ParseType.JSON:
            List = JSON(original,ReplaceValues(self.JsonField,BotData),self.Recursive,self.JTokenParsing)
            print(f"Parsed JSON {List} From {original[0:10]}......")
        elif self.ParseType == ParseType.REGEX:
            List = REGEX(original,ReplaceValues(self.RegexString,BotData),ReplaceValues(self.RegexOutput,BotData),self.Recursive)
            print(f"Parsed REGEX {List} From {original[0:10]}......")
        elif self.ParseType == ParseType.REGEX:
            List = REGEX(original,ReplaceValues(self.RegexString,BotData),ReplaceValues(self.RegexOutput,BotData),self.Recursive)
            print(f"Parsed REGEX {List} From {original[0:10]}......")
        elif self.ParseType == ParseType.CSS:
            List = CSS(original, self.CssSelector, self.AttributeName, self.CssElementIndex, self.Recursive)
            print(f"Parsed CSS {List} From {original[0:10]}......")
        else:
            pass

        InsertVariable(BotData, self.IsCapture, self.Recursive, List, self.VariableName, self.Prefix, self.Suffix, self.EncodeOutput, self.CreateEmpty)

class EncodingType(str, Enum):
    HEX = "HEX"
    BIN = "BIN"
    BASE64 = "BASE64"
    ASCII = "ASCII"
    UTF8 = "UTF8"
    UNICODE = "UNICODE"

class Conversion():
    def __init__(self) -> None:
        pass

    def ConvertFrom(self, input_string:str, encoding_type:EncodingType) -> bytes:
        if encoding_type == EncodingType.BASE64:
            inputBytes = input_string.encode('utf-8')
            base64_bytes = base64.b64decode(inputBytes)
            return base64_bytes

        elif encoding_type == EncodingType.HEX:
            return bytes.fromhex(input_string)

        elif encoding_type == EncodingType.BIN:
            numOfBytes = int(len(input_string) / 8)
            output = bytearray(numOfBytes)
            i = 0
            while i < numOfBytes:
                output[i] = int(input_string[8 * i: (8 * i) + 8], 2)
                i += 1
            return bytes(output)

        elif encoding_type == EncodingType.ASCII:
            return input_string.encode(encoding='ascii',errors='replace')

        elif encoding_type == EncodingType.UTF8:
            return input_string.encode(encoding='UTF-8',errors='replace')

        elif encoding_type == EncodingType.UNICODE:
            return input_string.encode(encoding='UTF-16',errors='replace')

    def ConvertTo(self, input_bytes:bytes, encoding_type:EncodingType) -> str:
        if encoding_type == EncodingType.BASE64:
            base64_bytes = base64.b64encode(input_bytes)
            return base64_bytes.decode()

        elif encoding_type == EncodingType.HEX:
            return input_bytes.hex()

        elif encoding_type == EncodingType.BIN:
            output = [f'{byte:0>8b}' for byte in input_bytes]
            return "".join(output)

        elif encoding_type == EncodingType.ASCII:
            return input_bytes.decode(encoding='ascii',errors='replace')

        elif encoding_type == EncodingType.UTF8:
            return input_bytes.decode(encoding='UTF-8',errors='replace')

        elif encoding_type == EncodingType.UNICODE:
            return input_bytes.decode(encoding='UTF-16',errors='replace')

def IsSubPathOf(parent_path, child_path):
    parent_path = os.path.abspath(os.path.realpath(parent_path))
    child_path = os.path.abspath(os.path.realpath(child_path))

    return os.path.commonpath([parent_path]) == os.path.commonpath([parent_path, child_path])
def Unescape(string:str):
    return string \
    .replace("\\r\\n", "\r\n") \
    .replace("\\n", "\n") \
    .replace("\\t", "\t")

def NotInCWD(cwd, path):
    return not IsSubPathOf(cwd, path)

from shutil import copyfile, move, rmtree

def string_escape(s, encoding='utf-8'):
    return (s.encode('latin1')
             .decode('unicode-escape')
             .encode('latin1')
             .decode(encoding))
class UtilityGroup(str, Enum):
    List = "List"
    Variable = "Variable"
    Conversion = "Conversion"
    File = "File"
    Folder = "Folder"

class VarAction(str, Enum):
    Split = "Split"

class ListAction(str, Enum):
    Create = "Create"
    Length = "Length"
    Join = "Join"
    Sort = "Sort"
    Concat = "Concat"
    Zip = "Zip"
    Map = "Map"
    Add = "Add"
    Remove = "Remove"
    RemoveValues = "RemoveValues"
    RemoveDuplicates = "RemoveDuplicates"
    Random = "Random"
    Shuffle = "Shuffle"

class FileAction(str, Enum):
    Exists = "Exists"
    Read = "Read"
    ReadLines = "ReadLines"
    Write = "Write"
    WriteLines = "WriteLines"
    Append = "Append"
    AppendLines = "AppendLines"
    Copy = "Copy"
    Move = "Move"
    Delete = "Delete"

class FolderAction(str, Enum):
    Exists = "Exists"
    Create = "Create"
    Delete = "Delete"
    
class BlockUtility:
    def __init__(self) -> None:
        self.Dict = {}
        self.list_name = None
        self.list_action = None
        self.Separator = None
        self.Ascending = True
        self.SecondListName = None
        self.ListIndex = None
        self.ListItem = None
        self.ListIndex = "0"
        self.ListComparisonTerm = None
        self.ListElementComparer = None
        self.VarName = None
        self.var_action = None
        self.SplitSeparator = None
        self.ConversionFrom = None
        self.ConversionTo = None
        self.file_action = None
        self.folder_action = None
        self.FolderPath = None
        self.InputString = ""
        self.isCapture = False
        self.group = None
        self.VariableName = ""
        self.block_type = "UTILITY"  
        self.label = ""  

    def FromLS(self, line:LineParser) -> None:
        if str(line.current).startswith("!"):
            return None

        self.group = ParseEnum(line)

        if self.group == UtilityGroup.List:

            self.list_name = ParseLiteral(line)
            self.list_action = ParseEnum(line)

            if self.list_action == ListAction.Join:
                self.Separator = ParseLiteral(line)

            elif self.list_action == ListAction.Sort:
                while Lookahead(line) == "Boolean":
                    boolean_name, boolean_value = SetBool(line,self)
                    
            elif self.list_action == ListAction.Map or \
                self.list_action == ListAction.Zip or \
                self.list_action == ListAction.Concat:
                self.SecondListName = ParseLiteral(line)

            elif self.list_action == ListAction.Add:
                self.ListItem = ParseLiteral(line)
                self.ListIndex = ParseLiteral(line)

            elif self.list_action == ListAction.Remove:
                self.ListIndex = ParseLiteral(line)

            elif self.list_action == ListAction.RemoveValues:
                self.ListElementComparer  = ParseEnum(line)
                self.ListComparisonTerm = ParseLiteral(line)
            else:
                pass

        elif self.group == UtilityGroup.Variable:
            self.VarName = ParseLiteral(line)
            self.var_action  = ParseEnum(line)
            if self.var_action == VarAction.Split:
                self.SplitSeparator = ParseLiteral(line)

        elif self.group == UtilityGroup.Conversion:
            self.ConversionFrom =ParseEnum(line)
            self.ConversionTo = ParseEnum(line)
            self.InputString = ParseLiteral(line)
        
        elif self.group == UtilityGroup.File:
            self.FilePath = ParseLiteral(line)
            self.file_action = ParseEnum(line)

            if self.file_action in [
                FileAction.Write, FileAction.WriteLines,
                FileAction.Append, FileAction.AppendLines,
                FileAction.Copy, FileAction.Move]:
                self.InputString = ParseLiteral(line)

        elif self.group == UtilityGroup.Folder:
            self.FolderPath = ParseLiteral(line)
            self.folder_action = ParseEnum(line)

        if not ParseToken(line,"Arrow",False,True):
            return self.Dict
            
        VARLB = ParseToken(line,"Parameter",True,True)
        if str(VARLB.upper()) == "VAR" or str(VARLB.upper()) == "CAP":
            if str(VARLB.upper()) == "CAP":
                self.Dict["IsCapture"] = True
                self.isCapture = True

        VariableName = ParseToken(line,"Literal",True,True)
        self.VariableName = VariableName

    def Process(self, BotData):
        print(f"BLOCK: {self.block_type}, GROUP: {self.group}")

        replacedInput = ReplaceValues(self.InputString,BotData)
        if self.group == UtilityGroup.List:
            list1 = BotData.Variables.GetList(self.list_name) or []
            list2 = BotData.Variables.GetList(self.SecondListName) or []
            item = ReplaceValues(self.ListItem, BotData)
            index  = int(ReplaceValues(self.ListIndex, BotData))

            if self.list_action == ListAction.Create:
                output = list1
                BotData.Variables.Set(CVV(self.VariableName, output, self.isCapture))
                print(f"ACTION: {ListAction.Create}, output: {output}")

            elif self.list_action == ListAction.Length:
                output = str(len(list1))
                BotData.Variables.Set(CVV(self.VariableName, output, self.isCapture))
                print(f"ACTION: {ListAction.Length}, output: {output}")

            elif self.list_action == ListAction.Join:
                output = self.Separator.join(list1)
                BotData.Variables.Set(CVV(self.VariableName, output, self.isCapture))
                print(f"ACTION: {ListAction.Join}, output: {output}")

            elif self.list_action == ListAction.Sort:
                output = sorted(list1)
                if not self.Ascending:
                    output = list(reversed(output))
                BotData.Variables.Set(CVV(self.VariableName, output, self.isCapture))
                print(f"ACTION: {ListAction.Sort}, output: {output}")

            elif self.list_action == ListAction.Concat:
                output = list1 + list2
                BotData.Variables.Set(CVV(self.VariableName, output, self.isCapture))
                print(f"ACTION: {ListAction.Concat}, output: {output}")
                
            elif self.list_action == ListAction.Zip:
                output = zip(list1, list2)
                output = [f"{a}{b}" for a, b in output]
                BotData.Variables.Set(CVV(self.VariableName, output, self.isCapture))
                print(f"ACTION: {ListAction.Zip}, output: {output}")

            elif self.list_action == ListAction.Map:
                output = zip(list1, list2)
                output = [{a: b} for a, b in output]
                BotData.Variables.Set(CVV(self.VariableName, output, self.isCapture))
                print(f"ACTION: {ListAction.Map}, output: {output}")

            elif self.list_action == ListAction.Add:
                variable = BotData.Variables.GetWithNameAndType(self.list_name, VARLB.List)
                if not variable: return

                if len(variable.Value) == 0: index = 0
                elif index < 0: index += len(variable.Value)
                variable.Value.insert(index, item)

                print(f"ACTION: {ListAction.Add}, output: {variable.Value}")

            elif self.list_action == ListAction.Remove:
                variable = BotData.Variables.GetWithNameAndType(self.list_name, VARLB.List)
                if not variable: return

                if len(variable.Value) == 0: index = 0
                elif index < 0: index += len(variable.Value)
                variable.Value.pop(index)

                print(f"ACTION: {ListAction.Remove}, output: {variable.Value}")

            elif self.list_action == ListAction.RemoveValues:
                output = [l for l in list1 if not Verify(
                    ReplaceValues(l, BotData), self.ListElementComparer, self.ListComparisonTerm
                )] 
                BotData.Variables.Set(CVV(self.VariableName, output, self.isCapture))
                print(f"ACTION: {ListAction.RemoveValues}, output: {output}")

            elif self.list_action == ListAction.RemoveDuplicates:
                output = list(dict.fromkeys(list1))
                BotData.Variables.Set(CVV(self.VariableName, output, self.isCapture))
                print(f"ACTION: {ListAction.RemoveDuplicates}, output: {output}")

            elif self.list_action == ListAction.Random:
                output = choice(list1)
                BotData.Variables.Set(CVV(self.VariableName, output, self.isCapture))
                print(f"ACTION: {ListAction.Random}, output: {output}")

            elif self.list_action == ListAction.Shuffle:
                output = list1
                shuffle(output)
                BotData.Variables.Set(CVV(self.VariableName, output, self.isCapture))
                print(f"ACTION: {ListAction.Shuffle}, output: {output}")

        elif self.group == UtilityGroup.Variable:

            if self.var_action == VarAction.Split:
                single = BotData.Variables.GetSingle(self.VarName)
                output = single.split(
                    ReplaceValues(self.SplitSeparator, BotData)
                )
                BotData.Variables.Set(CVV(self.VariableName, output, self.isCapture))
                print(f"Executed action {self.var_action} on variable {self.VarName} with outcome {output}")


        elif self.group == UtilityGroup.Conversion:
            conversionInputBytes = Conversion().ConvertFrom(replacedInput,self.ConversionFrom)
            conversionResult  = Conversion().ConvertTo(conversionInputBytes,self.ConversionTo)
            BotData.Variables.Set(CVV(self.VariableName, conversionResult, self.isCapture))
            print(f"Executed conversion {self.ConversionFrom} to {self.ConversionTo} on input {replacedInput} with outcome {conversionResult}")

        elif self.group == UtilityGroup.File:
            
            file = ReplaceValues(self.FilePath, BotData)
            if NotInCWD(BotData.cwd, file) == True:
                print("File path is out of bounds")
                return

            if self.file_action == FileAction.Exists:
                output = os.path.isfile(file)
                BotData.Variables.Set(CVV(self.VariableName, str(output), self.isCapture))
            
            elif self.file_action == FileAction.Read:
                try:
                    with open(file, "r", errors="ignore") as f:
                        output = f.read()
                        BotData.Variables.Set(CVV(self.VariableName, str(output), self.isCapture))

                except Exception as e:
                    print(e)
                    return

            elif self.file_action == FileAction.ReadLines:
                try:
                    with open(file, "r", errors="ignore") as f:
                        output = f.readlines()
                        BotData.Variables.Set(CVV(self.VariableName, output, self.isCapture))

                except Exception as e:
                    print(e)
                    return

            elif self.file_action == FileAction.Write:
                try:
                    with open(file, "w", errors="ignore") as f:
                        f.write(string_escape(replacedInput))
                except Exception as e:
                    print(e)
                    return

            elif self.file_action == FileAction.WriteLines:
                try:
                    with open(file, "w", errors="ignore") as f:
                        output = ReplaceValuesRecursive(self.InputString, BotData)
                        if type(output) == str:
                            f.writelines(string_escape(output))
                        elif type(output) == list:
                            f.writelines([string_escape(line) + "\n" for line in output])
                except Exception as e:
                    print(e)
                    return

            elif self.file_action == FileAction.Append:
                try:
                    with open(file, "a", errors="ignore") as f:
                        f.write(string_escape(replacedInput))

                except Exception as e:
                    print(e)
                    return

            elif self.file_action == FileAction.AppendLines:
                try:
                    with open(file, "a", errors="ignore") as f:
                        output = ReplaceValuesRecursive(self.InputString, BotData)
                        if type(output) == str:
                            f.writelines(string_escape(output))
                        elif type(output) == list:
                            f.writelines([string_escape(line) + "\n" for line in output])
                except Exception as e:
                    print(e)
                    return

            elif self.file_action == FileAction.Copy:
                fileCopyLocation = ReplaceValues(self.InputString, BotData)
                if NotInCWD(BotData.cwd,fileCopyLocation) == True:
                    print("File path is out of bounds")
                    return
                try:
                    copyfile(file, fileCopyLocation)
                except Exception as e:
                    print(e)
                    return

            elif self.file_action == FileAction.Move:
                fileMoveLocation = ReplaceValues(self.InputString, BotData)
                if NotInCWD(BotData.cwd,fileMoveLocation) == True:
                    print("File path is out of bounds")
                    return
                try:
                    move(file, fileMoveLocation)
                except Exception as e:
                    print(e)
                    return

            elif self.file_action == FileAction.Delete:
                if os.path.isfile(file):
                    os.remove(file)
                else:
                    return
            print(f"Executed action {self.file_action} on file {file}")
        elif self.group == UtilityGroup.Folder:
            folder = ReplaceValues(self.FolderPath, BotData)
            if NotInCWD(BotData.cwd, folder):
                print("File path is out of bounds")
                return

            if self.folder_action == FolderAction.Exists:
                output = os.path.isdir(folder)
                BotData.Variables.Set(CVV(self.VariableName, str(output), self.isCapture))
                print(f"Executed action {self.folder_action} on file {folder}")

            elif self.folder_action == FolderAction.Create:
                if os.path.isdir(folder) == False:
                    os.mkdir(folder)
                    BotData.Variables.Set(CVV(self.VariableName, str(folder), self.isCapture))
                    print(f"Executed action {self.folder_action} on file {folder}")

            elif self.folder_action == FolderAction.Delete:
                if os.path.isdir(folder):
                    if input(f"Are you sure you want to remove \"{folder}\" [y/n]: ").lower() == "y":
                        rmtree(folder)
                        print(f"Executed action {self.folder_action} on file {folder}")

def ToBase64(inputString:str):
    inputBytes = inputString.encode('utf-8')
    base64_bytes = base64.b64encode(inputBytes)
    return base64_bytes.decode('utf-8')


def FromBase64(base64EncodedData):
    base64EncodedBytes = base64EncodedData.encode('utf-8')
    base64_bytes = base64.b64decode(base64EncodedBytes)
    return base64_bytes.decode('utf-8')

class Hash(str, Enum):
    MD4 = "MD4"
    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    SHA384 = "SHA384"
    SHA512 = "SHA512"

class Crypto:

    def PBKDF2PKCS5(password:str, salt:str = None, saltSize:int = 8, iterations:int = 1, keyLength:str = 16, type:Hash = Hash.SHA1):
        if salt:
            deriveBytes = pbkdf2_hmac(
                hash_name = type.lower(), 
                password = str.encode(password),
                salt = base64.b64decode(salt), 
                iterations = iterations, 
                dklen = keyLength
            )
            return base64.b64encode(deriveBytes).decode()
        else:
            deriveBytes = pbkdf2_hmac(
                hash_name = type.lower(), 
                password = str.encode(password),
                salt = token_bytes(saltSize), 
                iterations = iterations,
                dklen = keyLength
            )
            return base64.b64encode(deriveBytes).decode()
            
    def MD4(rawInput):
        h = hashlib.new('md4')
        h.update(rawInput)
        return h.digest()
    def MD5(rawInput):
        h = hashlib.md5()
        h.update(rawInput)
        return h.digest()

    def SHA1(rawInput):
        h = hashlib.sha1()
        h.update(rawInput)
        return h.digest()

    def SHA256(rawInput):
        h = hashlib.sha256()
        h.update(rawInput)
        return h.digest()

    def SHA384(rawInput):
        h = hashlib.sha384()
        h.update(rawInput)
        return h.digest()

    def SHA512(rawInput):
        h = hashlib.sha512()
        h.update(rawInput)
        return h.digest()

    def HMACMD5(rawInput,rawKey):
        return hmac.new(rawKey, rawInput, hashlib.md5).digest()

    def HMACSHA1(rawInput,rawKey):
        return hmac.new(rawKey, rawInput, hashlib.sha1).digest()

    def HMACSHA256(rawInput,rawKey):
        return hmac.new(rawKey, rawInput, hashlib.sha256).digest()

    def HMACSHA384(rawInput,rawKey):
        return hmac.new(rawKey, rawInput, hashlib.sha384).digest()
        
    def HMACSHA512(rawInput,rawKey):
        return hmac.new(rawKey, rawInput, hashlib.sha512).digest()
    

class Browser(str, Enum):
    Chrome = "Chrome"
    Firefox = "Firefox"
    InternetExplorer = "InternetExplorer"
    Opera = "Opera"
    OperaMini = "OperaMini"


def random_window_version():

    windowsVersion = "Windows NT "
    random_number = randint(0,100)
    if random_number >= 1 and random_number <= 45:
        windowsVersion += "10.0"
    elif random_number > 45 and random_number <= 80:
        windowsVersion += "6.1"
    elif random_number > 80 and random_number <= 95:
        windowsVersion += "6.3"
    else:
         windowsVersion += "6.2"

    if random() <= 0.65:
        if random() <= 0.5:
            windowsVersion += "; WOW64"
        else:
            windowsVersion += "; Win64; x64"

    return windowsVersion
class UserAgent:
    def IEUserAgent():
        windowsVersion = random_window_version()
        version = None
        mozillaVersion = None
        trident = None
        otherParams = None

        if "NT 5.1" in windowsVersion:
            version = "9.0"
            mozillaVersion = "5.0"
            trident = "5.0"
            otherParams = ".NET CLR 2.0.50727; .NET CLR 3.5.30729"
        elif "NT 6.0" in windowsVersion:
            version = "9.0"
            mozillaVersion = "5.0"
            trident = "5.0"
            otherParams = ".NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.5.30729"
        else:
            random_number = randint(0, 2)

            if random_number == 0:
                version = "10.0"
                trident = "6.0"
                mozillaVersion = "5.0"

            elif random_number == 1:
                version = "10.6"
                trident = "6.0"
                mozillaVersion = "5.0"
            else:
                version = "11.0"
                trident = "7.0"
                mozillaVersion = "5.0"
            otherParams = ".NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E"

        return f"Mozilla/{mozillaVersion} (compatible; MSIE {version}; {windowsVersion}; Trident/{trident}; {otherParams})"

    def OperaUserAgent():
        version = None
        presto = None
        random_number = randint(0,3)
        if random_number == 0:
            version = "12.16"
            presto = "2.12.388"
        elif random_number == 1:
            version = "12.14"
            presto = "2.12.388"
        elif random_number == 2:
            version = "12.02"
            presto = "2.10.289"
        else:
            version = "12.00"
            presto = "2.10.181"

        return f"Opera/9.80 ({random_window_version()}); U) Presto/{presto} Version/{version}"

    def ChromeUserAgent():
        major = randint(62, 70)
        build = randint(2100, 3538)
        branchBuild = randint(0, 170)
        return f"Mozilla/5.0 ({random_window_version()}) AppleWebKit/537.36 (KHTML, like Gecko) " + f"Chrome/{major}.0.{build}.{branchBuild} Safari/537.36"

    def FirefoxUserAgent():
        FirefoxVersions = [64, 63, 62, 60, 58, 52, 51, 46, 45]
        version = choice(FirefoxVersions)
        return f"Mozilla/5.0 ({random_window_version()}; rv:{version}.0) Gecko/20100101 Firefox/{version}.0"

    def OperaMiniUserAgent():
        os = None
        miniVersion = None
        version = None
        presto = None

        random_number = randint(0, 2)
        if random_number == 0:
            os = "iOS"
            miniVersion = "7.0.73345"
            version = "11.62"
            presto = "2.10.229"
        elif random_number == 1:
            os = "J2ME/MIDP"
            miniVersion = "7.1.23511"
            version = "12.00"
            presto = "2.10.181"
        else:
            os = "Android"
            miniVersion = "7.5.54678"
            version = "12.02"
            presto = "2.10.289"

        return f"Opera/9.80 ({os}; Opera Mini/{miniVersion}/28.2555; U; ru) Presto/{presto} Version/{version}"

    def ForBrowser(browser):
        if browser == Browser.Chrome:
           return UserAgent.ChromeUserAgent() 
        elif browser == Browser.Firefox:
           return UserAgent.FirefoxUserAgent() 
        elif browser == Browser.InternetExplorer:
           return UserAgent.IEUserAgent()
        elif browser == Browser.Opera:
           return UserAgent.OperaUserAgent()
        elif browser == Browser.OperaMini:
           return UserAgent.OperaMiniUserAgent()
        else:
            return

    def Random():
        random_number = randint(0, 100)
        if random_number >= 1 and random_number <= 70:
            return UserAgent.ChromeUserAgent()
        if random_number > 70 and random_number <= 85:
            return UserAgent.FirefoxUserAgent()
        if random_number > 85 and random_number <= 91:
            return UserAgent.IEUserAgent()
        if random_number > 91 and random_number <= 96:
            return UserAgent.OperaUserAgent()
        
        return UserAgent.OperaMiniUserAgent()
    
def RandomString(localInputString:str):
    _lowercase = "abcdefghijklmnopqrstuvwxyz"
    _uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    _digits = "0123456789"
    _symbols = "\\!\"£$%&/()=?^'{}[]@#,;.:-_*+"
    _hex = _digits + "abcdef"
    _udChars = _uppercase + _digits
    _ldChars = _lowercase + _digits
    _upperlwr = _lowercase + _uppercase
    _ludChars = _lowercase + _uppercase + _digits
    _allChars = _lowercase + _uppercase + _digits + _symbols
    outputString = localInputString
    if "?l" in str(outputString):
        while "?l" in str(outputString):
            outputString = outputString.replace("?l",random.choice(list(_lowercase)),1)
    if "?u" in str(outputString):
        while "?u" in str(outputString):
            outputString = outputString.replace("?u",random.choice(list(_uppercase)),1)
    if "?d" in str(outputString):
        while "?d" in str(outputString):
            outputString = outputString.replace("?d",random.choice(list(_digits)),1)
    if "?s" in str(outputString):
        while "?s" in str(outputString):
            outputString = outputString.replace("?s",random.choice(list(_symbols)),1)
    if "?h" in str(outputString):
        while "?h" in str(outputString):
            outputString = outputString.replace("?h",random.choice(list(_hex)),1)
    if "?a" in str(outputString):
        while "?a" in str(outputString):
            outputString = outputString.replace("?a",random.choice(list(_allChars)),1)
    if "?m" in str(outputString):
        while "?m" in str(outputString):
            outputString = outputString.replace("?m",random.choice(list(_udChars)),1)
    if "?n" in str(outputString):
        while "?n" in str(outputString):
            outputString = outputString.replace("?n",random.choice(list(_ldChars)),1)
    if "?i" in str(outputString):
        while "?i" in str(outputString):
            outputString = outputString.replace("?i",random.choice(list(_ludChars)),1)
    if "?f" in str(outputString):
        while "?f" in str(outputString):
            outputString = outputString.replace("?f",random.choice(list(_upperlwr)),1)
    return outputString

def RandomNum(minNum,maxNum,padNum:bool):
                try:
                    randomNumString = str(randint(int(minNum),int(maxNum)))
                except Exception:
                    print("Failed to parse int")
                    return ""
                
                if padNum: randomNumString = randomNumString.rjust(len(str(maxNum)),"0")
                return randomNumString

                
class FunctionType(str, Enum):
    Constant = "Constant"
    Base64Encode = "Base64Encode"
    Base64Decode = "Base64Decode"
    Hash = "Hash"
    HMAC = "HMAC"
    Translate = "Translate"
    DateToUnixTime = "DateToUnixTime"
    Length = "Length"
    ToLowercase = "ToLowercase"
    ToUppercase = "ToUppercase"
    Replace = "Replace"
    RegexMatch = "RegexMatch"
    URLEncode = "URLEncode"
    URLDecode = "URLDecode"
    Unescape = "Unescape"
    HTMLEntityEncode = "HTMLEntityEncode"
    HTMLEntityDecode = "HTMLEntityDecode"
    UnixTimeToDate = "UnixTimeToDate"
    CurrentUnixTime = "CurrentUnixTime"
    UnixTimeToISO8601 = "UnixTimeToISO8601"
    RandomNum = "RandomNum"
    RandomString = "RandomString"
    Ceil = "Ceil"
    Floor = "Floor"
    Round = "Round"
    Compute = "Compute"
    CountOccurrences = "CountOccurrences"
    ClearCookies = "ClearCookies"
    RSAEncrypt = "RSAEncrypt"
    RSADecrypt = "RSADecrypt"
    RSAPKCS1PAD2 = "RSAPKCS1PAD2"
    Delay = "Delay"
    CharAt = "CharAt"
    Substring = "Substring"
    ReverseString = "ReverseString"
    Trim = "Trim"
    GetRandomUA = "GetRandomUA"
    AESEncrypt = "AESEncrypt"
    AESDecrypt = "AESDecrypt"
    PBKDF2PKCS5 = "PBKDF2PKCS5"

class BlockFunction:
    def __init__(self):
        self.VariableName = "" 
        self.IsCapture = False 
        self.InputString = "" 
        self.function_type = ""
        self.CreateEmpty = True
        self.Dict = {}
        self.UseRegex  = False
        self.ReplaceWhat = ""
        self.ReplaceWith = ""
        self.HashType = ""
        self.InputBase64 = False
        self.KeyBase64 = False
        self.HmacBase64 = False
        self.RandomZeroPad = False
        self.UserAgentBrowser = "Chrome"
        self.UserAgentSpecifyBrowser = False
        self.KdfSalt = ""
        self.KdfSaltSize = 8
        self.KdfIterations = 1
        self.KdfKeySize = 16
        self.KdfAlgorithm = "SHA1"
        self.TranslationDictionary = {}
        self.StopAfterFirstMatch = True
    def FromLS(self,line:LineParser):

        if str(line.current).startswith("!"):
            return None

        self.Dict = {} 

        self.Dict["IsCapture"] = False
        
        self.Dict["VariableName"] = ""

        self.Dict["InputString"] = ""

        self.Dict["Booleans"] = {}

        function_type  = ParseEnum(line)
        self.Dict["function_type"] = function_type
        self.function_type = function_type

        if function_type == FunctionType.Constant:
            pass

        elif function_type == FunctionType.Hash:
            HashType = ParseEnum(line)
            self.Dict["HashType"] = HashType
            self.HashType = HashType

            while Lookahead(line) == "Boolean":
                boolean_name, boolean_value = SetBool(line,self)
                self.Dict["Booleans"][boolean_name] = boolean_value
        
        elif function_type == FunctionType.HMAC:
            HashType = ParseEnum(line)
            self.Dict["HashType"] = HashType
            self.HashType = HashType
            HmacKey = ParseLiteral(line)
            self.Dict["HmacKey"] = HmacKey
            self.HmacKey = HmacKey
            while Lookahead(line) == "Boolean":
                boolean_name, boolean_value = SetBool(line,self)
                self.Dict["Booleans"][boolean_name] = boolean_value

        elif function_type == FunctionType.Translate:
            while Lookahead(line) == "Boolean":
                boolean_name, boolean_value = SetBool(line,self)
                self.Dict["Booleans"][boolean_name] = boolean_value
            self.Dict["TranslationDictionary"] = {}

            while line.current and Lookahead(line) == "Parameter":
                EnsureIdentifier(line, "KEY")
                k = ParseLiteral(line)
                EnsureIdentifier(line, "VALUE")
                v = ParseLiteral(line)
                self.Dict["TranslationDictionary"][k] = v
                self.TranslationDictionary[k] = v

        elif function_type == FunctionType.DateToUnixTime:
            self.Dict["DateFormat"] = ParseLiteral(line)

        elif function_type == FunctionType.UnixTimeToDate:
            DateFormat = ParseLiteral(line)
            self.DateFormat = DateFormat
            self.Dict["DateFormat"] = DateFormat
            if Lookahead(line) != "Literal":
                self.InputString = DateFormat
                self.DateFormat ="yyyy-MM-dd:HH-mm-ss"
                self.Dict["InputString"] = "yyyy-MM-dd:HH-mm-ss"

        elif function_type == FunctionType.Replace:
            ReplaceWhat = ParseLiteral(line)
            self.Dict["ReplaceWhat"] = ReplaceWhat
            self.ReplaceWhat = ReplaceWhat
            
            ReplaceWith = ParseLiteral(line)
            self.Dict["ReplaceWith"] = ReplaceWith
            self.ReplaceWith = ReplaceWith

            if Lookahead(line) == "Boolean":
                boolean_name, boolean_value = SetBool(line,self)
                self.Dict["Booleans"][boolean_name] = boolean_value

        elif function_type == FunctionType.RegexMatch:
            self.Dict["RegexMatch"] = ParseLiteral(line)

        elif function_type == FunctionType.RandomNum:
            if Lookahead(line) == "Literal":
                RandomMin = ParseLiteral(line)
                RandomMax = ParseLiteral(line)
                self.Dict["RandomMin"] = RandomMin
                self.Dict["RandomMax"] = RandomMax
                self.RandomMin = RandomMin
                self.RandomMax = RandomMax
            else:
                RandomMin = ParseLiteral(line)
                RandomMax = ParseLiteral(line)
                self.Dict["RandomMin"] = RandomMin
                self.Dict["RandomMax"] = RandomMax
                self.RandomMin = RandomMin
                self.RandomMax = RandomMax
            
            if Lookahead(line) == "Boolean":
                boolean_name, boolean_value = SetBool(line,self)
                self.Dict["Booleans"][boolean_name] = boolean_value
        
        elif function_type == FunctionType.CountOccurrences:
            StringToFind = ParseLiteral(line)
            self.StringToFind = StringToFind
            self.Dict["StringToFind"] = StringToFind

        elif function_type == FunctionType.CharAt:
            charIndex = ParseLiteral(line)
            self.charIndex = charIndex
            self.Dict["CharIndex"] = charIndex

        elif function_type == FunctionType.Substring:
            SubstringIndex = ParseLiteral(line)
            SubstringLength = ParseLiteral(line)
            self.SubstringIndex = SubstringIndex
            self.SubstringLength = SubstringLength
            self.Dict["SubstringIndex"] = SubstringIndex
            self.Dict["SubstringLength"] = SubstringLength

        elif function_type == FunctionType.RSAEncrypt:
            self.Dict["RsaN"] = ParseLiteral(line)
            self.Dict["RsaE"] = ParseLiteral(line)
            if Lookahead(line) == "Boolean":
                boolean_name, boolean_value = SetBool(line,self)
                self.Dict["Booleans"][boolean_name] = boolean_value

        elif function_type == FunctionType.RSAPKCS1PAD2:
            self.Dict["RsaN"] = ParseLiteral(line)
            self.Dict["RsaE"] = ParseLiteral(line)
        
        elif function_type == FunctionType.GetRandomUA:
            if ParseToken(line,"Parameter", False, False) == "BROWSER":
                EnsureIdentifier(line,"BROWSER")
                UserAgentBrowser = ParseEnum(line)
                self.UserAgentBrowser = UserAgentBrowser
                self.UserAgentSpecifyBrowser = True
                self.Dict["UserAgentBrowser"] = UserAgentBrowser
                self.Dict["Booleans"]["UserAgentSpecifyBrowser"] = True

        elif function_type == FunctionType.AESDecrypt:
            pass

        elif function_type == FunctionType.AESEncrypt:
            self.Dict["AesKey"] = ParseLiteral(line)
            self.Dict["AesIV"] = ParseLiteral(line)
            self.Dict["AesMode"] = ParseEnum(line)
            self.Dict["AesPadding"] = ParseEnum(line)

        elif function_type == FunctionType.PBKDF2PKCS5:
            if Lookahead(line) == "Literal":
                self.KdfSalt = ParseLiteral(line)
                self.KdfIterations = ParseInt(line)
                self.KdfKeySize = ParseInt(line)
                self.KdfAlgorithm = ParseEnum(line)
            else:
                self.KdfSaltSize = ParseInt(line)
                self.KdfIterations = ParseInt(line)
                self.KdfKeySize = ParseInt(line)
                self.KdfAlgorithm = ParseEnum(line)
        else:
            pass
        if Lookahead(line) == "Literal":
            inputString  = ParseLiteral(line)
            self.InputString = inputString
            self.Dict["InputString"] = inputString

        if not ParseToken(line,"Arrow",False,True):
            return self.Dict
            
        VARLB = ParseToken(line,"Parameter",True,True)
        if str(VARLB.upper()) == "VAR" or str(VARLB.upper()) == "CAP":
            if str(VARLB.upper()) == "CAP":
                self.Dict["IsCapture"] = True
                self.isCapture = True

        VariableName = ParseToken(line,"Literal",True,True)
        self.VariableName = VariableName
        self.Dict["VariableName"] = VariableName

    def Process(self,BotData):
        localInputStrings = ReplaceValuesRecursive(self.InputString,BotData)
        outputs = []

        for localInputString in localInputStrings:
            outputString = ""
            if self.function_type == FunctionType.Constant:
                outputString = localInputString

            elif self.function_type == FunctionType.Base64Encode:
                outputString = ToBase64(localInputString)

            elif self.function_type == FunctionType.Base64Decode:
                outputString = FromBase64(localInputString)

            elif self.function_type == FunctionType.Length:
                outputString = str(len(localInputString))

            elif self.function_type == FunctionType.ToLowercase:
                outputString = localInputString.lower()

            elif self.function_type == FunctionType.ToUppercase:
                outputString = localInputString.upper()

            elif self.function_type == FunctionType.Replace:
                if self.UseRegex:
                    outputString = re.sub(ReplaceValues(self.ReplaceWhat,BotData), ReplaceValues(self.ReplaceWith,BotData), localInputString)
                else:
                    outputString = localInputString.replace(ReplaceValues(self.ReplaceWhat,BotData),ReplaceValues(self.ReplaceWith,BotData))

            elif self.function_type == FunctionType.URLEncode:
                outputString = quote(localInputString,errors="replace")

            elif self.function_type == FunctionType.URLDecode:
                outputString = unquote(localInputString)

            elif self.function_type == FunctionType.Hash:
                outputString = self.GetHash(localInputString,self.HashType,self.InputBase64).lower()

            elif self.function_type == FunctionType.HMAC:
                 outputString = self.Hmac(localInputString,self.HashType,self.HmacKey,self.InputBase64,self.KeyBase64,self.HmacBase64)

            elif self.function_type == FunctionType.RandomNum:
                outputString = RandomNum(ReplaceValues(self.RandomMin,BotData),ReplaceValues(self.RandomMax,BotData),self.RandomZeroPad)

            elif self.function_type == FunctionType.RandomString:
                outputString = localInputString
                outputString = RandomString(outputString)

            elif self.function_type == FunctionType.CurrentUnixTime:
                outputString = str(int(time.time()))

            elif self.function_type == FunctionType.Ceil:
                outputString = str(math.ceil(float(localInputString)))

            elif self.function_type == FunctionType.Floor:
                outputString = str(math.floor(float(localInputString)))

            elif self.function_type == FunctionType.Round:
                outputString = str(round(float(localInputString)))

            elif self.function_type == FunctionType.CountOccurrences:
                outputString = str(localInputString.count(self.StringToFind))

            elif self.function_type == FunctionType.CharAt:
                outputString = str(localInputString[int(ReplaceValues(self.charIndex,BotData))])

            elif self.function_type == FunctionType.ReverseString:
                charArray = list(localInputString)
                charArray.reverse()
                outputString = "".join(charArray)

            elif self.function_type == FunctionType.Substring:
                outputString = localInputString[int(ReplaceValues(self.SubstringIndex,BotData)): int(ReplaceValues(self.SubstringIndex,BotData)) + int(ReplaceValues(self.SubstringLength, BotData))]

            elif self.function_type == FunctionType.GetRandomUA:
                if self.UserAgentSpecifyBrowser:
                    outputString = UserAgent.ForBrowser(self.UserAgentBrowser)
                else:
                    outputString = UserAgent.Random()

            elif self.function_type == FunctionType.Trim:
                outputString = localInputString.strip()

            elif self.function_type == FunctionType.UnixTimeToDate:
                outputString = datetime.fromtimestamp(int(localInputString),timezone.utc).strftime("%Y-%m-%d:%H-%M-%S")

            elif self.function_type == FunctionType.PBKDF2PKCS5:
                outputString = Crypto.PBKDF2PKCS5(localInputString, ReplaceValues(self.KdfSalt, BotData), self.KdfSaltSize, self.KdfIterations, self.KdfKeySize, self.KdfAlgorithm)

            elif self.function_type == FunctionType.Translate:
                outputString = localInputString
                for entryKey, entryValue in self.TranslationDictionary.items():
                    if entryKey in outputString:
                        outputString = outputString.replace(entryKey, entryValue)
                        if self.StopAfterFirstMatch: break
            elif self.function_type == FunctionType.Unescape:
                outputString = Unescape(localInputString)

            elif self.function_type == FunctionType.UnixTimeToISO8601:
                outputString = datetime.fromtimestamp(int(localInputString),timezone.utc).isoformat()

            elif self.function_type == FunctionType.ClearCookies:
                    BotData.CookiesSet(CVV("COOKIES",{},False,True))
            elif self.function_type == FunctionType.HTMLEntityEncode:
                outputString = escape(localInputString)
            elif self.function_type == FunctionType.HTMLEntityDecode:
                outputString = unescape(localInputString)
            else:
                pass
            outputs.append(outputString)

        print(f"Executed function {self.function_type} on input {localInputStrings} with outcome {outputString}")
        isList = len(outputs) > 1 or "[*]" in self.InputString or "(*)" in self.InputString or "{*}" in self.InputString
        InsertVariable(BotData,self.IsCapture,isList,outputs,self.VariableName,self.CreateEmpty)

    def GetHash(self,baseString:str,hashAlg:str,inputBase64:bool):
        if not inputBase64:
            rawInput = baseString.encode('utf-8')
        else:
            try:
                rawInput = base64.b64decode(baseString.encode('utf-8'))
            except Exception:
                return ""
        digest = bytearray()
        if hashAlg == "MD4":
            digest = Crypto.MD4(rawInput)
        elif hashAlg == "MD5":
            digest = Crypto.MD5(rawInput)
        elif hashAlg == "SHA1":
            digest = Crypto.SHA1(rawInput)
        elif hashAlg == "SHA256":
            digest = Crypto.SHA256(rawInput)
        elif hashAlg == "SHA384":
            digest = Crypto.SHA384(rawInput)
        elif hashAlg == "SHA512":
            digest = Crypto.SHA512(rawInput)
        return digest.hex()

    def Hmac(self, baseString:str,hashAlg,key:str,inputBase64:bool,keyBase64:bool,outputBase64:bool):
        rawInput = bytearray()
        rawKey = bytearray()
        signature = bytearray()
        if inputBase64:
            rawInput = base64.b64decode(baseString.encode('utf-8'))
        else:
            rawInput = baseString.encode('utf-8')

        if keyBase64:
            rawKey = base64.b64decode(key.encode('utf-8'))
        else:
            rawKey = key.encode('utf-8')

        if hashAlg == "MD5":
            signature  = Crypto.HMACMD5(rawInput,rawKey)

        elif hashAlg == "SHA1":
            signature  = Crypto.HMACSHA1(rawInput,rawKey)

        elif hashAlg == "SHA256":
            signature  = Crypto.HMACSHA256(rawInput,rawKey)

        elif hashAlg == "SHA384":
            signature  = Crypto.HMACSHA384(rawInput,rawKey)

        elif hashAlg == "SHA512":
            signature  = Crypto.HMACSHA512(rawInput,rawKey)
        else:
            return ""
        if outputBase64:
           return base64.b64encode(signature).decode("utf-8")
        else:
            return signature.hex().upper()

class BlockKeycheck:
    def __init__(self):
        self.Dict = {}
        self.KeyChains_Objects = []
        self.banOnToCheck = True
        self.banOn4XX = False
    def FromLS(self,line:LineParser):
        if str(line.current).startswith("!"):
            return None
        KeyChains = []
        self.KeyChains_Objects = []
        self.Dict = {}
        
        self.Dict["Booleans"] = {}
        while Lookahead(line) == "Boolean":
            boolean_name, boolean_value = SetBool(line,self)
            self.Dict["Booleans"][boolean_name] = boolean_value

        while line.current:
            EnsureIdentifier(line,"KEYCHAIN")
            KC = KeyChain()
            kc = {}
            kc["Keys"] = []
            KeyChainType = ParseEnum(line)
            
            kc["Type"] = KeyChainType
            KC.Type = KeychainType[KeyChainType]
            if kc.get("Type") == "CUSTOM" and Lookahead(line) == "Literal":
                kc["CustomType"] = ParseLiteral(line)
            KC_Mode = ParseEnum(line)
            kc["Mode"] = KC_Mode
            KC.Mode = KeychainMode[KC_Mode]

            while line.current and line.current.startswith("KEYCHAIN") == False:
                k = {}
                Key_Object = Key()
                EnsureIdentifier(line,"KEY")
                first = ParseLiteral(line)

                if CheckIdentifier(line,"KEY") or CheckIdentifier(line,"KEYCHAIN") or not line.current:
                    Key_Object.LeftTerm = "<SOURCE>"
                    Key_Object.Comparer = Comparer["Contains"]
                    Key_Object.RightTerm = first
                    k["LeftTerm"] = "<SOURCE>"
                    k["Comparer"] = "Contains"
                    k["RightTerm"] = first
                else:
                    Key_Object.LeftTerm = first
                    k["LeftTerm"] = first
                    Comparer__ = ParseEnum(line)
                    k["Comparer"] = Comparer__
                    Key_Object.Comparer = Comparer[Comparer__]
                    if Key_Object.Comparer.value != "Exists" and  Key_Object.Comparer.value != "DoesNotExist":
                        RightTerm__ = ParseLiteral(line)
                        k["RightTerm"] = RightTerm__
                        Key_Object.RightTerm = RightTerm__
                KC.Keys.append(Key_Object)
                kc["Keys"].append(k)
            self.KeyChains_Objects.append(KC)
            KeyChains.append(kc)

        self.Dict["KeyChains"] = KeyChains

    def Process(self,BotData):
        try:
            if BotData.ResponseCodeGet().startswith("4") and self.banOn4XX:
                BotData.status = BotData.BotStatus.BAN
                return
        except Exception:
            pass
        

        found = False

        for keychain in self.KeyChains_Objects:
            if keychain.CheckKeys(BotData):
                found = True
                if keychain.Type == KeychainType.Success:
                    BotData.status = BotData.BotStatus.SUCCESS

                elif keychain.Type == KeychainType.Failure:
                    BotData.status = BotData.BotStatus.FAIL
                elif keychain.Type == KeychainType.Ban:
                    BotData.status = BotData.BotStatus.BAN

        if not found and self.banOnToCheck:
            BotData.status = BotData.BotStatus.BAN

class MultipartContentType(str, Enum):
    String = "String"
    File = "File"

class MultipartContent:
    def __init__(self, Name:str, Value:str, Type:MultipartContentType, ContentType:str = "") -> None:
        self.Name = Name
        self.Value = Value
        self.Type = Type
        self.ContentType = ContentType
class OBRequest():
    def __init__(self) -> None:
        pass
    
    def Setup(self, auto_redirect:bool, timeout:int=30):
        self.session = Session()
        self.request = Request()
        self.timeout = timeout
        self.auto_redirect = auto_redirect

    def SetStandardContent(self, postData:str, contentType:str, Method:str, encodeContent:bool = False):
        if encodeContent:
            postData = quote(postData, "=&")
        if contentType:
            self.request.headers["Content-Type"] = contentType
            self.request.data = postData

        return

    def SetRawContent(self, rawData:str, contentType:str):
        if contentType:
            self.request.headers["Content-Type"] = contentType
            rData = Conversion().ConvertFrom(rawData,EncodingType.HEX)
            self.request.data = rData

    def SetBasicAuth(self, user:str, password:str):
        self.request.auth = HTTPBasicAuth(user, password)

    def SetMultipartContent(self, contents, boundary:str):
        self.request.files = []
        bdry = boundary or GenerateMultipartBoundary()
        self.request.headers["Content-Type"] = f"multipart/form-data; boundary={bdry}"
        for c in contents:
            if c.Type == MultipartContentType.String:
                self.request.files.append((c.Name, (c.Value)))
            elif c.Type == MultipartContentType.File:
                self.request.files.append((c.Name, open(c.Value, "rb")))
        
    def Perform(self, url, method, proxy):
        self.request.url = url
        self.request.method = method
        request = self.session.prepare_request(self.request)
        self.response = self.session.send(request, timeout=self.timeout, allow_redirects=self.auto_redirect, proxies=proxy)

        address = self.response.url
        responseCode = str(self.response.status_code)
        headers = dict(self.response.headers)
        cookies = dict(self.session.cookies)


        return (address, responseCode, headers, cookies)

    def SaveString(self, readResponseSource:bool, headers:dict):
        return self.response.text
    
    def SetHeaders(self, headers:dict, acceptEncoding:bool = False):
        for h in headers.items():
            replacedKey = h[0].replace("-","").lower()
            if replacedKey == "acceptencoding":
                headers["Accept"] = "*"
            elif replacedKey == "contenttype": 
                pass
            else:
                self.request.headers[h[0]] = h[1]

    def SetCookies(self, cookies:dict):
        self.request.cookies = cookies

def GenerateMultipartBoundary():
    string = ""
    for x in range(16):
        ch = chr(int(floor(26 * random.random() + 65)))
        string += ch.lower()
    return f"------WebKitFormBoundary{string}"

def ParseString(input_string, separator, count) -> list:
    return [ n.strip() for n in input_string.split(separator,count)]
class RequestType(str, Enum):
    Standard = "Standard"
    BasicAuth = "BasicAuth"
    Multipart = "Multipart"
    Raw = "Raw"

class MultipartContentType(str, Enum):
    String = "String"
    File = "File"

class ResponseType(str, Enum):
    String = "String"
    File = "File"
    Base64String = "Base64String"

class BlockRequest:
    def __init__(self,url=None):
        self.url = url
        self.request_type = RequestType.Standard
        self.auth_user = ""
        self.auth_pass = ""
        self.post_data = ""
        self.raw_data = ""
        self.method = "GET"
        self.custom_cookies = {}
        self.custom_headers = {}
        self.ContentType = ""
        self.auto_redirect = True
        self.read_response_source = True
        self.encode_content = False
        self.accept_encoding = True
        self.multipart_boundary = ""
        self.multipart_contents = []
        self.response_type = ResponseType.String
        self.download_path = ""
        self.output_variable = ""
        self.save_as_screenshot = False

    def FromLS(self,line:LineParser):
        if str(line.current).startswith("!"):
            return None

        method = ParseEnum(line)
        self.method = method

        url = ParseLiteral(line)
        self.url = url

        while Lookahead(line) == "Boolean":
            boolean_name, boolean_value = SetBool(line,self)

        while len(str(line.current)) != 0 and line.current.startswith("->") == False:
            parsed = ParseToken(line,"Parameter",True,True).upper()
            if parsed == "MULTIPART":
                self.request_type = RequestType.Multipart

            elif parsed == "BASICAUTH":
                self.request_type = RequestType.BasicAuth

            elif parsed == "STANDARD":
                self.request_type = RequestType.Standard

            elif parsed == "RAW":
                self.request_type = RequestType.Raw

            elif parsed == "CONTENT":
                post_data = ParseLiteral(line)
                self.post_data = post_data

            elif parsed == "RAWDATA":
                raw_data = ParseLiteral(line)
                self.raw_data = raw_data

            elif parsed == "STRINGCONTENT":
                stringContentPair = ParseString(ParseLiteral(line), ':', 2)
                self.multipart_contents.append(MultipartContent(stringContentPair[0], stringContentPair[1], MultipartContentType.String))
                
            elif parsed == "FILECONTENT":
                fileContentTriplet = ParseString(ParseLiteral(line), ':', 3)
                self.multipart_contents.append(MultipartContent(fileContentTriplet[0], fileContentTriplet[1], MultipartContentType.File, fileContentTriplet[3]))

            elif parsed == "COOKIE":
                cookiePair = ParseString(ParseLiteral(line), ':', 2)
                self.custom_cookies[cookiePair[0]] = cookiePair[1]

            elif parsed == "HEADER":
                headerPair = ParseString(ParseLiteral(line), ':', 2)
                self.custom_headers[headerPair[0]] = headerPair[1]

            elif parsed == "CONTENTTYPE":
                ContentType = ParseLiteral(line)
                self.ContentType = ContentType

            elif parsed == "USERNAME":
                auth_user = ParseLiteral(line)
                self.auth_user = auth_user

            elif parsed == "PASSWORD":
                auth_pass = ParseLiteral(line)
                self.auth_pass = auth_pass


            elif parsed == "BOUNDARY":
                multipart_boundary = ParseLiteral(line)
                self.multipart_boundary = multipart_boundary

            elif parsed == "SECPROTO":
                SecurityProtocol = ParseLiteral(line)
                self.SecurityProtocol = SecurityProtocol

            else:
                pass

        if line.current.startswith("->"):
            EnsureIdentifier(line, "->")
            outType = ParseToken(line,"Parameter",True,True)

            if outType.upper() == "STRING":
                self.response_type = ResponseType.String

            elif outType.upper() == "FILE":
                self.response_type = ResponseType.File
                download_path  = ParseLiteral(line)
                self.download_path = download_path
                while Lookahead(line) == "Boolean":
                    boolean_name, boolean_value = SetBool(line,self)

            elif outType.upper() == "BASE64":
                self.response_type = ResponseType.Base64String
                output_variable = ParseLiteral(line)
                self.output_variable = output_variable
    def Process(self,BotData:BotData):
        proxy = BotData.proxy
        local_url = ReplaceValues(self.url,BotData)
        request = OBRequest()
        request.Setup(self.auto_redirect)

        if self.request_type == RequestType.Standard:
            request.SetStandardContent(ReplaceValues(self.post_data, BotData), ReplaceValues(self.ContentType, BotData), self.method, self.encode_content)
        elif self.request_type == RequestType.BasicAuth:
            request.SetBasicAuth(ReplaceValues(self.auth_user, BotData), ReplaceValues(self.auth_pass, BotData))

        elif self.request_type == RequestType.Raw:
            request.SetRawContent(ReplaceValues(self.raw_data, BotData), ReplaceValues(self.ContentType, BotData))
        elif self.request_type == RequestType.Multipart:
            contents = []
            for m in self.multipart_contents:
                contents.append(MultipartContent(
                    Name = ReplaceValues(m.Name, BotData),
                    Value = ReplaceValues(m.Value, BotData),
                    ContentType = ReplaceValues(m.ContentType, BotData),
                    Type = m.Type
                ))
            request.SetMultipartContent(contents, ReplaceValues(self.multipart_boundary, BotData))

        cookies = {}
        cookieJar = BotData.CookiesGet()
        if cookieJar:
            cookies = cookieJar.Value

        for c in self.custom_cookies.items():
            cookies[ReplaceValues(c[0],BotData)] = cookies[ReplaceValues(c[1],BotData)]
        request.SetCookies(cookies)

        headers = {}
        for headerName, headerValue in self.custom_headers.items():
            headers[ReplaceValues(headerName,BotData)] = ReplaceValues(headerValue,BotData)
        request.SetHeaders(headers, self.accept_encoding)


        try:
            (Address, ResponseCode, ResponseHeaders, ResponseCookies) = request.Perform(self.url, self.method, proxy)
            print(f"{self.method} {local_url}")
        except Exception as e:
            print(e)
            return


        BotData.ResponseCodeSet(CVV("RESPONSECODE",ResponseCode,False,True))
        BotData.AddressSet(CVV("ADDRESS",Address,False,True))
        BotData.ResponseHeadersSet(CVV("HEADERS",ResponseHeaders,False,True))

        for cN,cV in ResponseCookies.items():
            cookies[cN] = cV
        BotData.CookiesSet(CVV("COOKIES",cookies,False,True))

        if self.response_type == ResponseType.String:
            ResponseSource = request.SaveString(self.read_response_source, ResponseHeaders)
            BotData.ResponseSourceSet(CVV("SOURCE",ResponseSource,False,True))
                

BlockMappings  = {"BYPASSCF":"BlockBypassCF" ,"SOLVECAPTCHA":"BlockSolveCaptcha" ,"REPORTCAPTCHA":"BlockReportCaptcha" ,"CAPTCHA":"BlockImageCaptcha" ,"FUNCTION":"BlockFunction" ,"KEYCHECK":"BlockKeycheck" ,"PARSE":"BlockParse" ,"RECAPTCHA":"BlockRecaptcha" ,"REQUEST":"BlockRequest" ,"TCP":"BlockTCP" ,"UTILITY":"BlockUtility" ,"BROWSERACTION":"SBlockBrowserAction" ,"ELEMENTACTION":"SBlockElementAction" ,"EXECUTEJS":"SBlockExecuteJS" ,"NAVIGATE":"SBlockNavigate"}

BlockMappings2  = {"BYPASSCF": None,
            "SOLVECAPTCHA": None,
            "REPORTCAPTCHA": None,
            "CAPTCHA": None,
            "FUNCTION": BlockFunction,
            "KEYCHECK": BlockKeycheck,
            "PARSE":BlockParse,
            "RECAPTCHA": None,
            "REQUEST": BlockRequest,
            "TCP": None,
            "UTILITY": BlockUtility,
            "BROWSERACTION": None,
            "ELEMENTACTION": None,
            "EXECUTEJS": None,
            "NAVIGATE": None}
def GetBlockType(line):
    try:
        return re.match('^!?(#[^ ]* )?([^ ]*)',line).group(2) 
    except Exception:
        return ""


def IsBlock(line) -> bool:
    if BlockMappings.get(GetBlockType(line)) == None:
        return False
    else:
        return True
def CompressedLines(config_text) -> list:
    i = 0
    isScript = False
    compressed = config_text.splitlines()
    while i < len(compressed) - 1 :
        if isScript == False and IsBlock(compressed[i]) and compressed[i + 1].startswith(" ") or compressed[i + 1].startswith("\t"):
            compressed[i] += " " + compressed[i + 1].strip()
            compressed.pop(i + 1)
        elif isScript == False and IsBlock(compressed[i]) and compressed[i + 1].startswith("! ") or compressed[i + 1].startswith("!\t"):
            compressed[i] += " " + compressed[i + 1][1:].strip()
            compressed.pop(i + 1)
        else:
            if compressed[i].startswith("BEGIN SCRIPT"):
                isScript = True
            elif compressed[i].startswith("END SCRIPT"):
                isScript = False

            i += 1
    return compressed

def Parse(input_line):
    input_line = input_line.strip()
    if not input_line:
        return None
    
    line = LineParser()
    line.current = input_line

    disabled = input_line.startswith("!")
    if disabled: 
        line.current = line.current[1:].strip() 

    label = ParseToken(line, "Label", False, True)
    
    identifier = ParseToken(line, "Parameter", True, True)
    
    block_class = BlockMappings2.get(identifier.upper()) 
    
    if block_class:
        try:
            block = block_class()

            if hasattr(block, 'label'):
                block.label = label
            
            block.block_type = identifier

            if hasattr(block, 'FromLS'):
                block.FromLS(line)
            
            return block
        except Exception as e:
            print(f"{TF.ERROR}Failed to create block {identifier}: {e}")
            return None
    else:
        print(f"{yw}Unknown block type: {identifier}{k}")
        return None
    
def ConfigToText(filepath:str) -> Union[str, None]:
    with open(filepath, 'r', encoding='utf-8') as file:
        data = file.read()

    pattern = re.compile(r"\[SETTINGS\]\n([\s\S]+)\[SCRIPT\]")

    match = pattern.search(data)

    if match:
        try:
            res1 = match.group(1).strip()
            res = data.replace(res1,'')
            res = res.replace('[SETTINGS]','')
            res = res.replace('[SCRIPT]','')
        except:
            res1 = match.group(1).strip()

        return res

class OpenBullet:
    def AddProxy(proxy:str, proxy_type:proxyType, hey=None) -> Union[dict, None]:
        ip = None
        port = None
        username = None
        password = None

        try:
            if proxy.count(":") == 1:
                ip, port = proxy.split(":", 1)
            elif proxy.count(":") == 3:
                username, password, ip, port = proxy.split(":", 3)
            
        except Exception:
            return None
        
        proxy_uri = None
        if username and password:
            proxy_uri = username + ":" + password + "@" + ip + ":" + port
        else:
            proxy_uri = ip + ":" + port

        request_proxy = {}
        if proxy_type == proxyType.HTTP or proxy_type == proxyType.HTTPS:
            request_proxy["http"] = "http://" + proxy_uri

        if proxy_type == proxyType.HTTP:
            request_proxy["https"] = "http://" + proxy_uri
        elif proxy_type == proxyType.HTTPS:
            request_proxy["https"] = "https://" + proxy_uri

        if proxy_type == proxyType.SOCKS4:
            request_proxy["http"] = "socks4://" + proxy_uri
            request_proxy["https"] = "socks4://" + proxy_uri
        elif proxy_type == proxyType.SOCKS5:
            request_proxy["http"] = "socks5://" + proxy_uri
            request_proxy["https"] = "socks5://" + proxy_uri
    
        return request_proxy
    
    def __init__(self, config:str, data:BotData = None, USER:str = None, PASS:str = None, 
                 output_path:str = None, proxy:Union[str, None] = None, 
                 proxy_type:Union[str, proxyType] = proxyType.HTTP) -> None:
        
        self.blocks = []
        self.config = config

        if not data:
            self.data = BotData()
        else:

            self.data = BotData(status=data.status, proxy=data.proxy)
            self.data.Variables = VariableList()

            for var in data.Variables.all:
                self.data.Variables.Set(CVV(var.Name, var.Value, var.IsCapture, var.Hidden))

        self.data.status = BotData.BotStatus.NONE
        self.data.Variables.Set(CVV("COOKIES", {}, False, True))
        self.data.Variables.Set(CVV("SOURCE", "", False, True))
        self.data.Variables.Set(CVV("RESPONSECODE", "0", False, True))
        self.data.Variables.Set(CVV("ADDRESS", "", False, True))
        self.data.Variables.Set(CVV("HEADERS", {}, False, True))

        self.data.session = requests.Session()
        self.data.session.verify = False 
        self.data.session.cookies.clear()  
    
        original_set_cookie = RequestsCookieJar.set_cookie
        
        def safe_set_cookie(self, cookie, *args, **kwargs):

            try:
                self.clear(cookie.domain, cookie.path, cookie.name)
            except:
                pass
            return original_set_cookie(self, cookie, *args, **kwargs)
        self.data.session.cookies.set_cookie = lambda cookie, *args, **kwargs: safe_set_cookie(
            self.data.session.cookies, cookie, *args, **kwargs
        )
        
        if proxy:
            request_proxy = self.AddProxy(proxy, proxy_type)
            self.data.proxy = request_proxy

        if USER:
            self.data.Variables.Set(CVV("USER", USER, False, True))
        if PASS:
            self.data.Variables.Set(CVV("PASS", PASS, False, True))
        
        if output_path:
            self.data.cwd = output_path
        else:
            self.data.cwd = os.getcwd()
    
    def parse(self):
        compressed = CompressedLines(self.config)
        for c in compressed:
            try:
                block = Parse(c)
            except Exception as e:
                print(f"Parse error: {e}")
                return
            if block: 
                self.blocks.append(block)
    
    def process(self):
        for block in self.blocks:
            if self.data.status.value in [self.data.BotStatus.FAIL.value, 
                                         self.data.BotStatus.BAN.value, 
                                         self.data.BotStatus.ERROR.value]:
                return
            
            try:
                if hasattr(block, 'Process'):
                    if hasattr(block, 'use_session'):
                        block.Process(self.data, self.data.session)
                    else:
                        block.Process(self.data)
                else:
                    print(f"Block {block.block_type} has no Process method")
                    
            except Exception as e:
                print(f"Process error in block {block.block_type if hasattr(block, 'block_type') else 'unknown'}: {e}")
                self.data.status = BotData.BotStatus.ERROR
                return 
    
    def run(self):
        self.blocks = []  
        self.data.session.cookies.clear()  
        
        self.parse()
        if self.blocks:
            self.process()
            return self.status()
        else:
            print("No blocks to process")
            return BotData.BotStatus.ERROR.value
    
    def status(self):
        return self.data.status.value if self.data.status else BotData.BotStatus.NONE.value
    
    def cleanup(self):
        if hasattr(self.data, 'session'):
            self.data.session.close()
            del self.data.session

def print_result(status, user, password):
    if 'SUCCESS' == status:
        print(f"{TF.SUCCESS}=> {user}:{password}\033[1;37m")
        with open('SUCCESS.txt','a') as suc:
            suc.write(f"{user}:{password}\n")
    elif 'BAN' == status:
        print(f"{TF.BAN}=> {user}:{password}\033[1;37m")
    elif 'FAIL' == status:
        print(f"{TF.FAIL}=> {user}:{password}\033[1;37m")
    elif 'NONE' == status:
        print(f"{TF.NONE}=> {user}:{password}\033[1;37m")
    elif 'ERROR' == status:
        print(f"{TF.ERROR}=> {user}:{password}\033[1;37m")
    elif 'RETRY' == status:
        print(f"{TF.RETRY}=> {user}:{password}\033[1;37m")
        with open('RETRY.txt','a') as ret:
            ret.write(f"{user}:{password}\n")
    elif 'CUSTOM' == status:
        print(f"{TF.CUSTOM}=> {user}:{password}\033[1;37m")
        with open('CUSTOM.txt','a') as cus:
            cus.write(f"{user}:{password}\n")

def save_result(status, user, password):
    if status == 'SUCCESS':
        with open('SUCCESS.txt','a') as f:
            f.write(f"{user}:{password}\n")
    elif status == 'RETRY':
        with open('RETRY.txt','a') as f:
            f.write(f"{user}:{password}\n")
    elif status == 'CUSTOM':
        with open('CUSTOM.txt','a') as f:
            f.write(f"{user}:{password}\n")

class ParallelProcessor:
    def __init__(self, config_text, proxy_list, combo_list, proxy_type, max_workers=5):
        self.config_text = config_text
        self.proxy_list = proxy_list
        self.combo_list = combo_list
        self.proxy_type = proxy_type
        self.max_workers = max_workers
        self.lock = threading.Lock()
        self.stats = {
            'total': 0, 'success': 0, 'fail': 0, 'retry': 0,
            'custom': 0, 'ban': 0, 'error': 0, 'none': 0
        }

        if proxy_list and len(proxy_list) == 1 and proxy_list[0] is None:
            self.proxy_list = [""]  
            self.proxy_type = None
            print(f"{k}[Parallel] Running without proxies{k}")
        elif not proxy_list:
            self.proxy_list = [""]
            self.proxy_type = None
            print(f"{k}[Parallel] No proxies, using direct connection{k}")
        
     
    def process_single(self, proxy, combo):

        try:
            UserPass = combo.strip().split(':')
            if len(UserPass) < 2:
                return None
            requests.cookies.RequestsCookieJar.set_cookie = lambda self, cookie, *args, **kwargs: None
            username = UserPass[0].strip()
            password = UserPass[1].strip()
            
            if proxy and proxy.strip():  
                proxy_to_use = proxy.strip()
                proxy_type_to_use = self.proxy_type
            else:
                proxy_to_use = None  
                proxy_type_to_use = None
            
            open_bullet = OpenBullet(
                config=self.config_text, 
                USER=username,
                PASS=password,
                proxy=proxy_to_use,  
                proxy_type=proxy_type_to_use 
            )
            
            status = open_bullet.run()

            with self.lock:
                self.stats['total'] += 1
                if status == 'SUCCESS':
                    self.stats['success'] += 1
                elif status == 'FAIL':
                    self.stats['fail'] += 1
                elif status == 'RETRY':
                    self.stats['retry'] += 1
                elif status == 'CUSTOM':
                    self.stats['custom'] += 1
                elif status == 'BAN':
                    self.stats['ban'] += 1
                elif status == 'ERROR':
                    self.stats['error'] += 1
                elif status == 'NONE':
                    self.stats['none'] += 1
            
            return {
                'user': username,
                'pass': password,
                'status': status,
                'proxy': proxy if proxy else 'DIRECT'
            }
        except Exception as e:
            print(f"{TF.ERROR}Error processing {combo[:20]}...: {e}")
            return None
    def print_stats(self):
        with self.lock:
            total = self.stats['total']
            if total == 0:
                return
            
            print(f"\n{gn}{'='*50}")
            print(f"📊 Parallel Processing Statistics")
            print(f"{yw}{'='*50}")
            print(f"{gn}✅ Success: {self.stats['success']} ({self.stats['success']/total*100:.1f}%)")
            print(f"{rd}❌ Fail: {self.stats['fail']} ({self.stats['fail']/total*100:.1f}%)")
            print(f"{be}🔄 Retry: {self.stats['retry']} ({self.stats['retry']/total*100:.1f}%)")
            print(f"{cn}🎨 Custom: {self.stats['custom']} ({self.stats['custom']/total*100:.1f}%)")
            print(f"{lrd}🚫 BAN: {self.stats['ban']} ({self.stats['ban']/total*100:.1f}%)")
            print(f"{lrd}💥 Error: {self.stats['error']} ({self.stats['error']/total*100:.1f}%)")
            print(f"{k}⚪ NONE: {self.stats['none']} ({self.stats['none']/total*100:.1f}%)")
            print(f"{'-'*50}")
            print(f"📈 Total Processed: {total}")
            print(f"{yw}{'='*50}\033[1;37m")
    
    def run_parallel(self):

        results = []
        
        print(f"{lgn}Starting parallel processing with {self.max_workers} workers...{k}")
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:

            tasks = []
            for proxy in self.proxy_list:
                for combo in self.combo_list:
                    tasks.append((proxy, combo))

            if len(tasks) > 1000:
                print(f"{yw}Limiting to first 1000 tasks for testing{k}")
                tasks = tasks[:1000]
            
            future_to_task = {}
            for proxy, combo in tasks:
                future = executor.submit(self.process_single, proxy, combo)
                future_to_task[future] = (proxy, combo)

            completed = 0
            for future in as_completed(future_to_task):
                completed += 1
                try:
                    result = future.result(timeout=60)
                    if result:
                        results.append(result)

                        status = result['status']
                        user = result['user']
                        password = result['pass']
                        
                        if status == 'SUCCESS':
                            print(f"{TF.SUCCESS}=> {user}:{password}\033[1;37m")
                            with open('SUCCESS.txt','a') as f:
                                f.write(f"{user}:{password}\n")
                        elif status == 'RETRY':
                            print(f"{TF.RETRY}=> {user}:{password}\033[1;37m")
                            with open('RETRY.txt','a') as f:
                                f.write(f"{user}:{password}\n")
                        elif status == 'CUSTOM':
                            print(f"{TF.CUSTOM}=> {user}:{password}\033[1;37m")
                            with open('CUSTOM.txt','a') as f:
                                f.write(f"{user}:{password}\n")
                        elif status == 'FAIL':
                            print(f"{TF.FAIL}=> {user}:{password}\033[1;37m")
                        elif status == 'BAN':
                            print(f"{TF.BAN}=> {user}:{password}\033[1;37m")

                        if completed % 10 == 0:
                            elapsed = time.time() - start_time
                            rate = completed / elapsed if elapsed > 0 else 0
                            print(f"{k}[{completed}/{len(tasks)}] Speed: {rate:.1f}/s{k}")
                            
                except Exception as e:
                    print(f"{TF.ERROR}Task failed: {e}")
        
        elapsed = time.time() - start_time
        print(f"{lgn}Parallel processing completed in {elapsed:.1f}s{k}")
        self.print_stats()
        
        return results

def init_output_files():

    output_files = ['SUCCESS.txt', 'RETRY.txt', 'CUSTOM.txt', 'ERROR_LOG.txt']
    
    for file in output_files:
        if not os.path.exists(file):
            with open(file, 'w') as f:
                f.write(f"# OpenBullet Pro Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            print(f"{lgn}Created output file: {file}{k}")


lock = f"""{k}                                                                                                                       
                                                           
    ..                                               ..    
    -.-#==:                                     .==#=.:.   
    -:   :#++.                               .+=#-   .+    
     +-    .**+.                           .++#:    :+     
      *+.  .: #**:                       .**#..:   +#.     
       =#+   =:-#+#.                   .#*#=.+   =%+       
        .+#= :++:-#+*.               .+**+:++- -#*.        
          .##%: .* +#*#-           :*##*.*: .%%#.          
            -#%#: .+-*#*+##:   .##*+#*==: .*%#=            
              =%%*:+.+:.=##+#.**##=..+:=-+%%+              
                +%%.  .=#.+%#*%%* *=.  .#%*                
                 #%#.-*. ==.+#++*+ .+=.*%%.                
                 :##%-.    +-.##=** ::###-                 
                   +#%#.-   .*:.##-##%%*                   
                    -%%%#:-   .*::##=#=                    
                   #+*%%%%*.-   :#.:%#=#:                  
                .#*+%+.%%%%%+-:   -*.-#*+#:                
              .**=%+.++ #%%%%%=-:   -*.=#++#.              
             *#=## +*    #%%##%%-=.   =*.*%+##.            
           =#=##:=*.   =:#%%+ =#%#-=.   ++.*#=#+.          
         =#+#%:=*.   -:#%%*     =#%#:=   .*+.##=#+         
       :#*##--#:   ::*%%#.        *#%*:-   .#=:##*%=       
      :###=-#-   .:+%%#.           .*%%*::   :#=-##*-      
    *##%#-#=   .:=#%#:               .#%%+:.   :#-#####    
    =#:+:#+.  :-%%#-                   :#%%=:.  =#-+:#*    
     -%*=#+#*:#%#=                       :#%#:+#=#=+#=     
       *%*:####=                           :####-+%#.      
         =##%=                               :%##+.        
                                                                  
                    
"""
bullet = f"""{k}
 ____   __ __  _      _        ___  ______ 
|    \ |  T  T| T    | T      /  _]|      T
|  o  )|  |  || |    | |     /  [_ |      |
|     T|  |  || l___ | l___ Y    _]l_j  l_j
|  O  ||  :  ||     T|     T|   [_   |  |  
|     |l     ||     ||     ||     T  |  |  
l_____j \__,_jl_____jl_____jl_____j  l__j  

	{gn}Telegram: @Specter_OG\n\n
"""
RUN = f"{pe} Config executed!"
version = f"""
{lgn}    A tool that executes OpenBullet configurations   
\033[1;37m    Version : 2.1.2
{lrd}    Git & Telegram : @esfelorm     \n\n            
"""
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description='OpenBullet Pro - Config Runner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --config test.loli --combos combos.txt
  %(prog)s --config config.anom --combos list.txt --proxy-type socks5 --proxies proxies.txt
  %(prog)s --config test.loli --combos data.txt --no-proxy --parallel --workers 10
        """
    )
    
    parser.add_argument('--config', '-c', required=True, help='Path to config file (.loli, .anom, etc.)')
    parser.add_argument('--combos', '-u', required=True, help='Path to combos file (user:pass format)')
    
    parser.add_argument('--proxies', '-p', help='Path to proxies file (optional)')
    parser.add_argument('--proxy-type', '-t', default='http', 
                       choices=['http', 'https', 'socks4', 'socks5'], 
                       help='Proxy type (default: http)')
    
    parser.add_argument('--no-proxy', action='store_true', help='Run without proxies')
    parser.add_argument('--parallel', '-P', action='store_true', help='Enable parallel processing')
    parser.add_argument('--workers', '-w', type=int, default=5, 
                       help='Number of workers for parallel mode (default: 5)')
    parser.add_argument('--output', '-o', default='.', help='Output directory for results')
    parser.add_argument('--silent', '-s', action='store_true', help='Silent mode (no banners)')
    parser.add_argument('--delay', '-d', type=float, default=0, 
                       help='Delay between requests in seconds')
    
    args = parser.parse_args()

    if not os.path.exists(args.config):
        print(f'{TF.ERROR}! Config file not found: {args.config}')
        exit(1)
    
    if not os.path.exists(args.combos):
        print(f'{TF.ERROR}! Combos file not found: {args.combos}')
        exit(1)
    
    if args.proxies and not os.path.exists(args.proxies):
        print(f'{TF.ERROR}! Proxies file not found: {args.proxies}')
        exit(1)
    
    if not args.silent:
        clear()
        ToSleep(lock, 0.0)
        ToSleep(version, 0.05)
    
    print(f"{lgn}Loading files...{k}")
    
    try:
        config_text = ConfigToText(args.config)
        if not config_text:
            print(f'{TF.ERROR}! Empty or invalid config file')
            exit(1)
    except Exception as e:
        print(f'{TF.ERROR}! Error reading config: {e}')
        exit(1)
    
    try:
        with open(args.combos, 'r', encoding='utf-8', errors='ignore') as f:
            combo_list = [line.strip() for line in f if line.strip()]
        print(f"{lgn}✓ Loaded {len(combo_list)} combos{k}")
    except Exception as e:
        print(f'{TF.ERROR}! Error reading combos: {e}')
        exit(1)
    
    proxy_list = []
    proxy_type = args.proxy_type
    
    if args.no_proxy:
        print(f"{yw}Running without proxies{k}")
        proxy_list = [None] 
        proxy_type = None
    elif args.proxies:
        try:
            with open(args.proxies, 'r', encoding='utf-8', errors='ignore') as f:
                proxy_list = [line.strip() for line in f if line.strip()]
            print(f"{lgn}✓ Loaded {len(proxy_list)} proxies ({proxy_type}){k}")
        except Exception as e:
            print(f'{TF.ERROR}! Error reading proxies: {e}')
            exit(1)
    else:
        print(f"{yw}No proxies file specified, running without proxies{k}")
        proxy_list = [None]
        proxy_type = None
    
    if len(combo_list) == 0:
        print(f'{TF.ERROR}! No combos loaded')
        exit(1)
    
    if not args.no_proxy and args.proxies and len(proxy_list) == 0:
        print(f'{TF.ERROR}! No proxies loaded')
        exit(1)

    if not args.silent:
        time.sleep(1)
        clear()
        ToSleep(bullet, 0.0015)
        ToSleep(RUN, 0.01)
        print(f"\n{gn}{'='*50}")
        print(f"📋 Execution Summary")
        print(f"{'='*50}{k}")
        print(f"📁 Config: {args.config}")
        print(f"👥 Combos: {len(combo_list)}")
        print(f"🛡️ Proxies: {len(proxy_list) if proxy_list and proxy_list[0] else 'None'}")
        print(f"⚡ Mode: {'Parallel' if args.parallel else 'Sequential'}")
        if args.parallel:
            print(f"👷 Workers: {args.workers}")
        print(f"📊 Output: {args.output}")
        print(f"{gn}{'='*50}\n")
        
    warnings.filterwarnings('ignore')
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    os.makedirs(args.output, exist_ok=True)
    
    if args.parallel:
        print(f"{lgn}Starting parallel processing with {args.workers} workers...{k}")
        
        processor = ParallelProcessor(
            config_text=config_text,
            proxy_list=proxy_list if proxy_list[0] else [None],
            combo_list=combo_list,
            proxy_type=proxy_type,
            max_workers=args.workers
        )
        
        processor.run_parallel()
        
    else:
        print(f"{lgn}Starting sequential processing...{k}")
        
        start_time = time.time()
        processed = 0
        total_combinations = len(proxy_list) * len(combo_list)

        stats = {
            'success': 0,
            'retry': 0,
            'custom': 0,
            'fail': 0,
            'ban': 0,
            'none': 0,
            'error': 0,
            'invalid': 0
        }
        
        for proxy in proxy_list:
            for combo in combo_list:
                processed += 1
                
                UserPass = combo.split(':', 1)  
                if len(UserPass) < 2:
                    print(f"{TF.ERROR}Invalid combo format: {combo}")
                    stats['invalid'] += 1
                    continue
                requests.cookies.RequestsCookieJar.set_cookie = lambda self, cookie, *args, **kwargs: None
                username = UserPass[0].strip()
                password = UserPass[1].strip()
                
                try:
                    open_bullet = OpenBullet(
                        config=config_text, 
                        USER=username,
                        PASS=password,
                        proxy=proxy if proxy else None,
                        proxy_type=proxy_type if proxy else None,
                        output_path=args.output
                    )
                    
                    status = open_bullet.run()

                    if status == 'SUCCESS':
                        stats['success'] += 1
                        print(f"{TF.SUCCESS}=> {username}:{password}\033[1;37m")
                        with open(os.path.join(args.output, 'SUCCESS.txt'), 'a', encoding='utf-8') as f:
                            f.write(f"{username}:{password}\n")
                    elif status == 'RETRY':
                        stats['retry'] += 1
                        print(f"{TF.RETRY}=> {username}:{password}\033[1;37m")
                        with open(os.path.join(args.output, 'RETRY.txt'), 'a', encoding='utf-8') as f:
                            f.write(f"{username}:{password}\n")
                    elif status == 'CUSTOM':
                        stats['custom'] += 1
                        print(f"{TF.CUSTOM}=> {username}:{password}\033[1;37m")
                        with open(os.path.join(args.output, 'CUSTOM.txt'), 'a', encoding='utf-8') as f:
                            f.write(f"{username}:{password}\n")
                    elif status == 'FAIL':
                        stats['fail'] += 1
                        print(f"{TF.FAIL}=> {username}:{password}\033[1;37m")
                        with open(os.path.join(args.output, 'FAIL.txt'), 'a', encoding='utf-8') as f:
                            f.write(f"{username}:{password}\n")
                    elif status == 'BAN':
                        stats['ban'] += 1
                        print(f"{TF.BAN}=> {username}:{password}\033[1;37m")
                        with open(os.path.join(args.output, 'BAN.txt'), 'a', encoding='utf-8') as f:
                            f.write(f"{username}:{password}\n")
                    elif status == 'NONE':
                        stats['none'] += 1
                        print(f"{TF.NONE}=> {username}:{password}\033[1;37m")
                    elif status == 'ERROR':
                        stats['error'] += 1
                        print(f"{TF.ERROR}=> {username}:{password}\033[1;37m")
                        with open(os.path.join(args.output, 'ERROR.txt'), 'a', encoding='utf-8') as f:
                            f.write(f"{username}:{password} | Error\n")

                    if args.delay > 0:
                        time.sleep(args.delay)

                    if processed % 10 == 0:
                        elapsed = time.time() - start_time
                        rate = processed / elapsed if elapsed > 0 else 0
                        remaining = total_combinations - processed
                        eta = remaining / rate if rate > 0 else 0
                        
                        print(f"{k}[{processed}/{total_combinations}] "
                              f"Speed: {rate:.1f}/s | "
                              f"ETA: {eta//3600:.0f}h {(eta%3600)//60:.0f}m{k}")
                        
                except Exception as e:
                    stats['error'] += 1
                    print(f"{TF.ERROR}Error processing {username}: {e}")
                    with open(os.path.join(args.output, 'ERROR_LOG.txt'), 'a', encoding='utf-8') as f:
                        f.write(f"{username}:{password} | {e}\n")
        
        elapsed = time.time() - start_time
        total_valid = processed - stats['invalid']

        print(f"\n{yw}{'='*60}")
        print(f"📊 {gn}FINAL STATISTICS")
        print(f"{yw}{'='*60}{k}")

        print(f"⏱️ Time: {elapsed:.1f}s")
        print(f"📈 Total Checks: {processed}")
        print(f"⚡ Average Speed: {processed/elapsed:.1f} checks/s" if elapsed > 0 else "⚡ Average Speed: 0.0 checks/s")
        print('-'*60)

        print(f"{gn}✅ SUCCESS: {stats['success']} ({stats['success']/total_valid*100:.1f}%)")
        print(f"{be}🔄 RETRY: {stats['retry']} ({stats['retry']/total_valid*100:.1f}%)")
        print(f"{cn}🎨 CUSTOM: {stats['custom']} ({stats['custom']/total_valid*100:.1f}%)")
        print(f"{rd}❌ FAIL: {stats['fail']} ({stats['fail']/total_valid*100:.1f}%)")
        print(f"{lrd}🚫 BAN: {stats['ban']} ({stats['ban']/total_valid*100:.1f}%)")
        print(f"{k}⚪ NONE: {stats['none']} ({stats['none']/total_valid*100:.1f}%)")
        print(f"{lrd}💥 ERROR: {stats['error']} ({stats['error']/total_valid*100:.1f}%)")
        print(f"{g}⚠️ INVALID: {stats['invalid']}{k}")

        print(f"{'-'*60}")
        print(f"📁 Output Directory: {os.path.abspath(args.output)}")

        output_files = {
            'SUCCESS.txt': stats['success'],
            'RETRY.txt': stats['retry'],
            'CUSTOM.txt': stats['custom'],
            'FAIL.txt': stats['fail'],
            'BAN.txt': stats['ban'],
            'ERROR.txt': stats['error']
        }
        
        for filename, count in output_files.items():
            filepath = os.path.join(args.output, filename)
            if os.path.exists(filepath) and count > 0:
                file_size = os.path.getsize(filepath)
                print(f"📄 {filename}: {count} results ({file_size/1024:.1f} KB)")
        
        print(f"{gn}{'='*60}{k}")

        print(f"\n{yw}💡 For next run:{k}")
        if stats['retry'] > 0:
            print(f"  - Run RETRY.txt with: python openbullet.py --config {args.config} --combos {os.path.join(args.output, 'RETRY.txt')}")
        if stats['ban'] > stats['success'] * 0.5:  
            print(f"  - Consider using better proxies or reducing workers")
        
        print(f"\n{gn}✅ Processing completed!{k}")
