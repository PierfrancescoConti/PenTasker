#!/usr/bin/env python3

from GUI import Gui, Gui2
from threading import Thread
from protocols import * 
from reporter import * 
from os import system, name, path, makedirs, getuid, listdir
from os.path import isfile, join
from glob import glob
from tkinter import ttk
from time import gmtime, strftime, time
import subprocess
import sys
import PySimpleGUI as sg
import re 
import json
import tkinter as tk






def print_usage():
    s='''
\nUsage:
 _____________________________________________________________________________
| ./pentasker.py               |          Start the GUI                       |
| ./pentasker.py <URL/IP>      |          Start from CLI                      |
|______________________________|______________________________________________|
| Other arguments for the CLI:                                                |
| ./pentasker.py -u <URL/IP> [-t NUMTHREADS] [-r RISK] [-m MODE]              |
|                            [-y TOOL1,TOOL2,...] [-n TOOL1,TOOL2,...]        |
|                                                                             |
|   -h, --help                 |  Prints this Usage message                   |
|                              |                                              |
|   -u, --url URL/IP           |  URL/IP to scan                              |
|   -f, --file URLs.txt        |  Input list of targets from a file           |
|   -t, --threads NUMTHREADS   |  Number of threads to scan (default: 5)      |
|   -r, --risk RISK            |  Risk level (from 0 to 5) (default: 4)       |
|   -m, --mode MODE            |  Scan mode (f=fast, c=complete) (default: f) |
|   -v, --verbose              |  Verbose mode on                             |
|   -y, --yes TOOL1,TOOL2,...  |  Choose tools to run                         |
|   -n, --no TOOL1,TOOL2,...   |  Run all the tools less the ones defined     |
|______________________________|______________________________________________|


Tool legend:
    ./pentasker -u 127.0.0.1 -y nikto,vulscan,lrh,testssl,dirsearch,rhsa,iis,legion,custom
 __________________________________________________________________________
|    Nikto -> nikto                   |     TestSSL.sh -> testssl          |
|    VulScan -> vulscan               |     DirSearch -> dirsearch         |
|    LiteRespH -> lrh                 |     RHsecapi -> rhsa               |
|    IIS Shortname Scanner -> iis     |     Legion -> legion               |        
|    Custom tools -> custom           |                                    |
|_____________________________________|____________________________________| 

'''
    print(s)
    exit()



def argparser():

    if '-h' in sys.argv or '--help' in sys.argv:
        print_usage()
    elif '-u' not in sys.argv and '--url' not in sys.argv and '-f' not in sys.argv and '--file' not in sys.argv:
        print('\n\033[31;1mMissing "-u", "--url" or "-f", "--file" arguments.\033[0m')
        print_usage()
    elif ('-y' in sys.argv and '-n' in sys.argv) or ('-y' in sys.argv and '--no' in sys.argv) or ('--yes' in sys.argv and '-n' in sys.argv) or ('--yes' in sys.argv and '--no' in sys.argv):
        print('\n\033[31;1mYES or NO? I\'m confused...\033[0m')
        print_usage()
    elif ('-u' in sys.argv and '-f' in sys.argv) or ('-y' in sys.argv and '--file' in sys.argv) or ('--url' in sys.argv and '-f' in sys.argv) or ('--url' in sys.argv and '--file' in sys.argv):
        print('\n\033[31;1mPlease insert only url OR file (not together).\033[0m')
        print_usage()
    

    values={}
    values['-tool0-']=True
    values['-tool1-']=True
    values['-tool2-']=False
    values['-tool3-']=False
    values['-tool4-']=False
    values['-tool5-']=False
    values['-tool6-']=False
    values['-tool7-']=False
    values['-tool8-']=False
    values['-tool9-']=False
    values['-custom-']=False
    values['-VERBOSE-']=False
    values['-THREADS-']=5
    values['-RISK-']=4
    values['-RADIO1-']=True
    values['-RADIO2-']=False

    if '-y' not in sys.argv and '--yes' not in sys.argv and '-n' not in sys.argv and '--no' not in sys.argv:
        print('\n\033[33;1mNo tool selected, I assume you want all of them.\033[0m')
        values['-tool2-']=True
        values['-tool3-']=True
        values['-tool4-']=True
        values['-tool5-']=True
        values['-tool6-']=True
        values['-tool7-']=True
        values['-tool8-']=True
        values['-tool9-']=True
        values['-custom-']=True

    for i in range(0, len(sys.argv)):
        try:
            if sys.argv[i]=='-u' or sys.argv[i]=='--url': 
                values["-URL-"]= sys.argv[i+1]
            if sys.argv[i]=='-f' or sys.argv[i]=='--file': 
                targets=open(sys.argv[i]+1).read()
                targets=targets.strip()
                values['-URL-']=targets.replace("\n","§")
            if sys.argv[i]=='-t' or sys.argv[i]=='--threads': 
                values["-THREADS-"]= int(sys.argv[i+1])
            if sys.argv[i]=='-r' or sys.argv[i]=='--risk': 
                if int(sys.argv[i+1])>5 or int(sys.argv[i+1])<0:
                    print('\n\033[31;1mRisk must be a value between 0 and 5\033[0m')
                    print_usage()
                values["-RISK-"]= int(sys.argv[i+1])
            if sys.argv[i]=='-y' or sys.argv[i]=='--yes': 
                ltools = sys.argv[i+1].split(',')
                for e in ltools:
                    if e.strip() == "nikto":
                        values['-tool2-']=True
                        print("2")
                    elif e.strip() == "vulscan":
                        values['-tool3-']=True
                        print("3")
                    elif e.strip() == "testssl":
                        values['-tool4-']=True
                        print("4")
                    elif e.strip() == "dirsearch":
                        values['-tool5-']=True
                        print("5")
                    elif e.strip() == "legion":
                        values['-tool6-']=True
                        print("6")
                    elif e.strip() == "lrh":
                        values['-tool7-']=True
                        print("7")
                    elif e.strip() == "rhsa":
                        values['-tool8-']=True
                        print("8")
                    elif e.strip() == "iis":
                        values['-tool9-']=True
                        print("9")
                    elif e.strip() == "custom":
                        values['-custom-']=True
                        print("c")
                    else:
                        print('\n\033[31;1mInvalid tool name: \033[0m'+e)
                        print_usage()
            if sys.argv[i]=='-n' or sys.argv[i]=='--no': 
                ltools = sys.argv[i+1].split(',')
                values['-tool2-']=True
                values['-tool3-']=True
                values['-tool4-']=True
                values['-tool5-']=True
                values['-tool6-']=True
                values['-tool7-']=True
                values['-tool8-']=True
                values['-tool9-']=True
                values['-custom-']=True
                for e in ltools:
                    if e.strip() == "nikto":
                        values['-tool2-']=False
                    elif e.strip() == "vulscan":
                        values['-tool3-']=False
                    elif e.strip() == "testssl":
                        values['-tool4-']=False
                    elif e.strip() == "dirsearch":
                        values['-tool5-']=False
                    elif e.strip() == "legion":
                        values['-tool6-']=False
                    elif e.strip() == "lrh":
                        values['-tool7-']=False
                    elif e.strip() == "rhsa":
                        values['-tool8-']=False
                    elif e.strip() == "iis":
                        values['-tool9-']=False
                    elif e.strip() == "custom":
                        values['-custom-']=False
                    else:
                        print('\n\033[31;1mInvalid tool name: \033[0m'+e)
                        print_usage()
            if sys.argv[i]=='-m' or sys.argv[i]=='--mode':
                if sys.argv[i+1]=='f':
                    values["-RADIO1-"]= True
                    values["-RADIO2-"]= False
                elif sys.argv[i+1]=='c':
                    values["-RADIO2-"]= True
                    values["-RADIO1-"]= False
                else:
                    print('\n\033[31;1mCan\'t undersand the scan mode.\033[0m')
                    print_usage()
            if sys.argv[i]=='-v' or sys.argv[i]=='--verbose':
                values["-VERBOSE-"]= True
        except:
            print("\033[31;1mSomething went wrong with the following argument: \033[0m"+sys.argv[i])
            exit()

    return values


def start_cli():
    values=argparser()
    launch(values)




# Utils
def clear(): 
  
    # for windows 
    if name == 'nt': 
        _ = system('cls') 
  
    # for mac and linux(here, os.name is 'posix') 
    else: 
        _ = system('clear') 

def printLogo():
    clear()
    print(
        '''

\033[31;1mMM""""""`YM                 M""""""""M                 dP                      
\033[31;1mMM  mmmm  M                 M___  ___M                 88                      
\033[37;1mM'  _____.M .d888b. 88d88b. MMMM  MMMM .d888b. .d888b. 88 .dP  .d888b. 88d88b. 
\033[37;1mMM  MMMMMMM 88oood8 88' `88 MMMM  MMMM 88' `88 Y8oooo. 8888"   88oood8 88' `88 
\033[37;1mMM  MMMMMMM 88.  .. 88   88 MMMM  MMMM 88. .88      88 88 `8b. 88.  .. 88      
\033[32;1mMM  MMMMMMM `8888P' dP   dP MMMM  MMMM `8888P8 `8888P' dP  `YP `8888P' dP      
\033[32;1mMMMMMMMMMMM                 MMMMMMMMMM                                          
\033[0m                                                                            
        '''
    )

regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$'''

def checkIP(Ip):
    if(re.search(regex, Ip)):  
        return True  
    else:  
        return False


def isANint(s):
    try: 
        int(s)
        return True
    except ValueError:
        return False


def get_ports(output0):
    ports=[]
    services=[]
    out=output0.split('\n')
    for line in out:
        p=line.split('/')[0]
        if isANint(p):
            ports.append(p)
            s=line.split(' ')[-1]
            if "http-" in s:
                s="http"
            services.append(s)
        
    return ports, services

# Return 1 if v2 is smaller, 
# -1 if v1 is smaller,, 
# 0 if equal 
def versionCompare(v1, v2): 

      
    # This will split both the versions by '.' 
    arr1 = v1.split(".")  
    arr2 = v2.split(".")  

    n = len(arr1) 
    m = len(arr2) 
      
    # converts to integer from string 
    arr1 = [int(i) for i in arr1] 
    arr2 = [int(i) for i in arr2] 
   
    # compares which list is bigger and fills  
    # smaller list with zero (for unequal delimeters) 
    if n>m: 
      for i in range(m, n): 
         arr2.append(0) 
    elif m>n: 
      for i in range(n, m): 
         arr1.append(0) 
      
    # returns 1 if version 1 is bigger and -1 if 
    # version 2 is bigger and 0 if equal 
    for i in range(len(arr1)): 
      if arr1[i]>arr2[i]: 
         return 1
      elif arr2[i]>arr1[i]: 
         return -1
    return 0


# returns most critical CVE in retlist
def getbest(retlist):       
    for lobj in retlist:
        if "SEVERITY : Critical" in lobj:
            return lobj.split("\n")[0].strip()+" (Critical)\n"
    for lobj in retlist:
        if "SEVERITY : Important" in lobj:
            return lobj.split("\n")[0].strip()+" (High)\n"
    for lobj in retlist:
        if "SEVERITY : Moderate" in lobj:
            return lobj.split("\n")[0].strip()+" (Moderate)\n"
    for lobj in retlist:
        if "SEVERITY : Low" in lobj:
            return lobj.split("\n")[0].strip()+" (Low)\n"


def no_colors(output):
    out = output.replace("[m","")
    out = out.replace("[0m","")
    out = out.replace("[1m","")
    out = out.replace("[7m","")
    out = out.replace("[31m","")
    out = out.replace("[32;1m","")
    out = out.replace("[33m","")
    out = out.replace("[35m","")
    out = out.replace("[36m","")
    out = out.replace("[92m","")
    out = out.replace("\\x0D","")
    for i in range(0,100):
        out = out.replace("["+str(i)+";1m","")
        out = out.replace("["+str(i)+";0m","")
        out = out.replace("[0;"+str(i)+"m","")
        out = out.replace("[1;"+str(i)+"m","")
    return out


# Thread Calls
def call_nikto(values, ip_addr, port, diz, verbose):
    output, error=task_nikto(values, ip_addr, port)
    output=output.decode()
    if error!=None:
        print("ERROR!")
    output = clean_out_nikto(output)
    x=False
    for X in diz["tabs"]:
        if X['tool']=='Nikto':
            x=True
            X['output'].append((str(port),no_colors(output)))
            break
    if x==False:
        data={
            'tool':'Nikto',
            'output':[(str(port),no_colors(output))]
        }
        diz["tabs"].append(data)
    if verbose:
        print('\033[44;1m   Nikto                                                                      \033[0m\n')
        print(output)
        print('\033[44;1m                                                                              \033[0m')
        print('------------------------------------------------------------------------------')
    else:
        print('\033[44;1m   Nikto - completed                                                          \033[0m\n')


def call_vulscan(values, ip_addr, p,diz,verbose):
    output, error=task_vulscan(values, ip_addr, p)
    output=output.decode()
    if error!=None:
        print("ERROR!")
    output = clean_out_vulscan(output)
    x=False
    for X in diz["tabs"]:
        if X['tool']=='VulScan':
            x=True
            X['output'].append((str(p),no_colors(output)))
            break
    if x==False:
        data={
            'tool':'VulScan',
            'output':[(str(p),no_colors(output))]
        }
        diz["tabs"].append(data)
    if verbose:
        print('\033[44;1m   VulScan                                                                    \033[0m\n')
        print("\nResults collected inside the project file.\n")
        print('\033[44;1m                                                                              \033[0m')
        print('------------------------------------------------------------------------------')
    else:
        print('\033[44;1m   VulScan - completed                                                        \033[0m\n')


def call_testssl(values, ip_addr, p, num_threads,diz,verbose):
    ip_addr+=":"+p
    output, error=task_testssl(values, ip_addr, num_threads)
    output=output.decode()
    if error!=None:
        print("ERROR!")
    
    x=False
    for X in diz["tabs"]:
        if X['tool']=='TestSSL.sh':
            x=True
            X['output'].append((str(p),no_colors(output)))
            break
    if x==False:
        data={
            'tool':'TestSSL.sh',
            'output':[(str(p),no_colors(output))]
        }
        diz["tabs"].append(data)

    output = clean_out_testssl(output)
    if verbose:
        print('\033[44;1m   TestSSL.sh                                                                 \033[0m\n')
        print(output[:-3])
        print('\033[44;1m                                                                              \033[0m')
        print('------------------------------------------------------------------------------')
    else:
        print('\033[44;1m   TestSSL.sh - completed                                                     \033[0m\n')


def call_dirsearch(values, url, p, num_threads,diz,verbose):
    output, error=task_dirsearch(values, url, p, num_threads)
    output=output.decode()
    if error!=None:
        print("ERROR!")
    output, fpath = clean_out_dirsearch(output)    
    if verbose:
        print('\033[44;1m   DirSearch                                                                  \033[0m\n')
        print(output)
        print('\033[44;1m                                                                              \033[0m')
        print('------------------------------------------------------------------------------')
    else:
        print('\033[44;1m   DirSearch - completed                                                      \033[0m\n')

    x=False
    for X in diz["tabs"]:
        if X['tool']=='DirSearch':
            x=True
            X['output'].append((str(p),no_colors(open(fpath,'r').read())))
            break
    if x==False:
        data={
            'tool':'DirSearch',
            'output':[(str(p),no_colors(open(fpath,'r').read()))]
        }
        diz["tabs"].append(data)


def call_literesph(url,p,diz,verbose):
    output, error=task_literesph(url,p)
    output=output.decode()
    if error!=None:
        print("ERROR!")
    #output = clean_out_literesph(output)       # output too perfect, no need to clean
    x=False
    for X in diz["tabs"]:
        if X['tool']=='LiteRespH':
            x=True
            X['output'].append((str(p),no_colors(output)))
            break
    if x==False:
        data={
            'tool':'LiteRespH',
            'output':[(str(p),no_colors(output))]
        }
        diz["tabs"].append(data)
    if verbose:
        print('\033[44;1m   LiteRespH                                                                  \033[0m\n')
        print(output)
        print('\033[44;1m                                                                              \033[0m')
        print('------------------------------------------------------------------------------')
    else:
        print('\033[44;1m   LiteRespH - completed                                                      \033[0m\n')
    

def call_rhsecapi(product,version,diz,verbose):
    output, error=task_rhsecapi(product)
    output=output.decode()
    if error!=None:
        print("ERROR!")
    output = clean_out_rhsecapi(output, product, version)
    x=False
    for X in diz["tabs"]:
        if X['tool']=='RHsecapi':
            x=True
            X['output'].append((product,no_colors(output)))
            break
    if x==False:
        data={
            'tool':'RHsecapi',
            'output':[(product,no_colors(output))]
        }
        diz["tabs"].append(data)
    if verbose:
        print('\033[44;1m   RHsecapi                                                                   \033[0m\n')
        print(output)
        print('\033[44;1m                                                                              \033[0m')
        print('------------------------------------------------------------------------------')
    else:
        print('\033[44;1m   RHsecapi - completed                                                       \033[0m\n')


def call_iis_ss(url,p,diz,verbose):
    output, error=task_iis_ss(url,p)
    output=output.decode()
    if error!=None:
        print("ERROR!")
    output = clean_out_iis_ss(output)

    x=False
    for X in diz["tabs"]:
        if X['tool']=='IIS Shortname Scanner':
            x=True
            X['output'].append((str(p),no_colors(output)))
            break
    if x==False:
        data={
            'tool':'IIS Shortname Scanner',
            'output':[(str(p),no_colors(output))]
        }
        diz["tabs"].append(data)
    if verbose:
        print('\033[44;1m   IIS Shortname Scanner                                                      \033[0m\n')
        print(output)
        print('\033[44;1m                                                                              \033[0m')
        print('------------------------------------------------------------------------------')
    else:
        print('\033[44;1m   IIS Shortname Scanner - completed                                          \033[0m\n')

def call_legion(ip_addr,protocol,p,diz,verbose):
    output, error=task_legion(ip_addr,protocol,p)
    output=output.decode()
    if error!=None:
        print("ERROR!")
    # output diventa il contenuto di tutti i file che finiscono per .out: /root/.legion/<HOST>/<proto>/<port>/*.out         TODO PERMISSION DENIED -> sudo cat *
    mypath="/root/.legion/"+ip_addr+"/"+protocol.name+"/"+p+"/"
    output=''
    bashCommand = "sudo ls " + mypath
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    o,e = process.communicate()
    onlyfiles = [join(mypath, f) for f in o.decode().split("\n") if ".out" in f]
    for f in onlyfiles:
        bashCommand = "sudo cat " + f
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        o,e = process.communicate()
        output+=o.decode()

    # output = clean_out_legion(output)

    x=False
    for X in diz["tabs"]:
        if X['tool']=='Legion':
            x=True
            X['output'].append((str(p),no_colors(output)))
            break
    if x==False:
        data={
            'tool':'Legion',
            'output':[(str(p),no_colors(output))]      # get from file
        }
        diz["tabs"].append(data)
    if verbose:
        print('\033[44;1m   Legion                                                                     \033[0m\n')
        print(output)
        print('\033[44;1m                                                                              \033[0m')
        print('------------------------------------------------------------------------------')
    else:
        print('\033[44;1m   Legion - completed                                                         \033[0m\n')



# Tasks
def task_nslookup(values, url):
    bashCommand = "nslookup "+url
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    return process.communicate()

def task_nmap(values, ip_addr, ports, services):
    if values['-RADIO1-']:          # Fast
        if len(ports)==0:
            bashCommand = "nmap -T" + str(int(values['-RISK-'])) + " "+ip_addr
            process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
            output, error = process.communicate()
            output=output.decode("UTF-8")
            ports,services = get_ports(output)

        if len(ports)==0:
            print("\033[31;1mNo ports detected... Maybe the host is down.\033[0m ")
        else:
            ######## RILANCIARE IL COMANDO CON -A #########
            bashCommand = "nmap -T" + str(int(values['-RISK-'])) + " -A -p "
            for p in ports:
                bashCommand+=p+','
            bashCommand=bashCommand[:-1]+' '+ip_addr
            print('\033[32;1mDetected ports:\033[0m '+ ', '.join(ports) +'\n')
            process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
            output, error =  process.communicate()
            output=output.decode("UTF-8")
        
    else:
        bashCommand = "sudo nmap -sU -T" + str(int(values['-RISK-'])) + " -p- "+ip_addr
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        output, error =  process.communicate()
        output=output.decode("UTF-8")
        ports = get_ports(output)
        if len(ports)==0:
            print("\033[33;1mNo ports detected... Maybe the host is down.\033[0m")
        else:
            ######## RILANCIARE IL COMANDO CON -A #########
            bashCommand = "sudo nmap -sU -T" + str(int(values['-RISK-'])) + " -A -p "
            for p in ports:
                bashCommand+=p+','
            bashCommand=bashCommand[:-1]+' '+ip_addr
            print('\033[32;1mDetected ports:\033[0m '+ ', '.join(ports) +'\n')
            process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
            output, error =  process.communicate()
            output=output.decode("UTF-8")

    return output, ports, services



def task_nikto(values, ip_addr, port):
    if port=='0':
        bashCommand = "nikto -h "+ip_addr
    else:
        bashCommand = "nikto -p "+port+" -h "+ip_addr
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    return process.communicate()

def task_vulscan(values, ip_addr, p):
    bashCommand = "nmap -T" + str(int(values['-RISK-'])) + " -sV --script=tools/vulscan/vulscan.nse -p "+p+' '+ip_addr
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    return process.communicate()

def task_dirsearch(values, url, p, num_threads):
    bashCommand = "python3 tools/dirsearch/dirsearch.py -u http://" + url + ":"+p+" -e ,html,txt,php,aspx -t " + str(num_threads)
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    return process.communicate()

def task_testssl(values, ip_addr, num_threads):
    bashCommand = "./tools/testssl.sh/testssl.sh " + ip_addr
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    return process.communicate()

def task_literesph(url,p):
    bashCommand = "python3 tools/LiteRespH/literesph.py " + url+":"+p
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    return process.communicate()

def task_rhsecapi(product):
    bashCommand = "./tools/rhsecapi/rhsecapi.py  --q-package " + product + " --extract-cves -f severity,cvss,upstream_fix,details"
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    return process.communicate()

def task_iis_ss(url,p):
    bashCommand = "java -jar tools/IIS-ShortName-Scanner/iis_shortname_scanner.jar " + url + ":" + p + " tools/IIS-ShortName-Scanner/config.xml"
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    return process.communicate()

def task_legion(ip_addr,protocol,p):
    bashCommand = "sudo python3 tools/legion/legion.py --proto "+ protocol.name +" --host "+ip_addr+" -p "+p+" -r --notuse dirsearch,nikto"
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    return process.communicate()







# Cleaners
def clean_out_nslookup(output,isAip, ip_addr):
    if isAip:
        out=output.split('\n\n')
        name=out[0].split('\n')[-1]
        domain=name[name.find('name = ')+7:-1]
        return out[0]+'\n', ip_addr, domain
    else:
        domain=ip_addr
        out=output.split('\n')
        ret=''
        x=0
        for line in out:
            if 'canonical name' in line or 'Name:' in line:
                ret+=line + '\n'
            else:
                if 'Address' in line and x==0:
                    x+=1
                elif 'Address' in line and x==1:
                    ip_addr=line.split(' ')[1]
                    x+=1
                    ret+=line + '\n'
                elif 'Address' in line and x>1:
                    ret+=line + '\n'
                    continue
        return ret, ip_addr, domain


def clean_out_nmap(output):
    try:
        return output.split('\n\n')[1]+'\n'
    except:
        print("Some problem occurred... maybe the scan is too fast")       #DEBUG
        return output

def clean_out_nikto(output):
    out=output.split('\n')
    ret=''
    for line in out:
        if 'Nikto' in line or 'Start Time:' in line or 'End Time:' in line or 'items checked:' in line or 'host(s) tested' in line:
            continue
        else:
            ret+=line + '\n'
    return ret

def clean_out_vulscan(output):
    return output.split('\n\n')[1]+'\n'

def clean_out_testssl(output):
    out=output.split('\n')
    ret=''
    x=False
    for line in out:
        if ' Start ' in line or ' Done ' in line:
            ret+=line + '\n\n'
        elif 'Rating (experimental)' in line:
            x=True
            ret+=line + '\n'
        elif x==False:
            continue
        else:
            ret+=line + '\n'
    return ret

def clean_out_dirsearch(output):
    out=output.split('\n')
    ret=''
    x=False
    fpath=''
    for line in out:
        if 'Output' in line:
            fpath=line.split(":")[1].strip()
        elif 'Extensions:' in line:
            x=True
            ret+=line + '\n'
        elif 'Error Log:' in line or 'Output File:' in line or '] 400 - ' in line or '] 401 - ' in line or '] 402 - ' in line or '] 403 - ' in line or '] 404 - ' in line or x==False:
            continue
        else:
            ret+=line + '\n'
    return ret, fpath

def clean_out_literesph(output):               # output too perfect, no need to clean
    return output

def clean_out_rhsecapi(output, product, version):
    cves=''
    best=''
    out=output.split('\n\n')[1:]
    retlist=[]
    x=False
    for obj in out:
        lobj=obj.split("\n")
        for line in lobj:
            if "UPSTREAM_FIX" in line:
                tok=line.split(" ")
                x=False
                for t in tok:
                    if product.lower() in t.lower():
                        x=True
                    regexp = re.compile(r'\d+(\.\d+)+')
                    if regexp.search(t) and x:
                        v1=version
                        v2=t.strip()
                        for letter in 'QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm,;:][-_ ':
                            v1=v1.replace(letter,'')
                            v2=v2.replace(letter,'')
                        v1=v1.strip(".")
                        v2=v2.strip(".")
                        a=versionCompare(v1,v2)    
                        if a==0 or a==-1:
                            retlist.append(obj)
                            break
                        else:
                            x=False


    if retlist==[]: retlist.append("No CVEs found for given product.")
    else:
        best=getbest(retlist)
        for lobj in retlist:
            l=lobj.split("\n")
            for line in l:
                if "CVE" in line and "  " not in line :
                    cves+=line.strip()+", "
        

    ret="\033[32;1m"+product+"/"+version+"\033[0m: "+best+cves[:-2]+"\n\n"
    for e in retlist:
        ret+=e+"\n\n"
    return ret

def clean_out_iis_ss(output):               # output too perfect, no need to clean
    out=output.split('\n')
    ret=''
    x=False
    for line in out:
        if '# IIS Short Name (8.3) Scanner' in line:
            continue
        else:
            ret+=line + '\n'
    return ret

def clean_out_legion(output):               # output too perfect, no need to clean
    '''out=output.split('\n')
    ret=''
    x=False
    for line in out:
        if '# IIS Short Name (8.3) Scanner' in line:
            continue
        else:
            ret+=line + '\n'
    return ret'''
    return output       #TODO






def call_custom(url,diz, verbose):               # you can CUSTOMIZE this if needed
    output, error=task_custom(url)
    if error!=None:
        print("ERROR!")
    #output = clean_out_custom(output)       # output too perfect, no need to clean
    data={
        'tool':'Custom scripts',
        'output':output
    }
    diz["tabs"].append(data)
    if verbose:
        print('\033[44;1m   Custom Scripts                                                             \033[0m\n')
        print(output)
        print('\033[44;1m                                                                              \033[0m')
        print('------------------------------------------------------------------------------')
    else:
        print('\033[44;1m   Custom Scripts - completed                                                 \033[0m\n')


def task_custom(url):
    output = ""
    for f in glob("tools/_custom/*.sh"):
        output += "\n\n     ------------- \033[32;1m"+ f.split("/")[-1] + "\033[0m -------------     \n\n"
        bashCommand = "./" + f + " " + url   # runs all .sh scripts inside the ./tools/_custom/ directory
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        o, e = process.communicate()
        output += o.decode()
    for f in glob("tools/_custom/*.py"):
        output += "\n\n     ------------- \033[32;1m"+ f.split("/")[-1] + "\033[0m -------------     \n\n"
        bashCommand = "python3 " + f + " " + url   # runs all .py scripts inside the ./tools/_custom/ directory
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        o, e = process.communicate()
        output += o.decode()
        output = output[2:]
    return output,None      # assert error is None


# function to filter useless rows from output
def clean_out_custom(output):
    out=output.split('\n')
    ret=''
    for line in out:
        if 'Accepted word' in line:         # Whitelist: rows accepted if contain the specified word(s)
            ret+=line + '\n'
        elif 'Word' in line or 'Not Accepted word:' in line:         # Blacklist: rows deleted from output if contain the specified word(s) 
            continue
        else:
            ret+=line + '\n'
    return ret





#___________________________________________________________________________________________________________________________________________________________#
#___________________________________________________________________________________________________________________________________________________________#
#___________________________________________________________________________________________________________________________________________________________#
#___________________________________________________________________________________________________________________________________________________________#
#___________________________________________________________________________________________________________________________________________________________#
#___________________________________________________________________________________________________________________________________________________________#
#___________________________________________________________________________________________________________________________________________________________#
#___________________________________________________________________________________________________________________________________________________________#
#___________________________________________________________________________________________________________________________________________________________#
#___________________________________________________________________________________________________________________________________________________________#





# Tasks Caller
def tasks(values, url, verbose):
    if url=="":
        print("\033[31;1mEmpty URL.\033[0m ")
    if values['-tool6-'] and getuid() != 0:
        print("To execute legion I need sudo.")
        bashCommand = "sudo id"
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        print(process.communicate()[0].decode())
    if values['-RADIO2-'] and getuid() != 0:
        print("To execute an UDP scan with nmap I need sudo.")
        bashCommand = "sudo id"
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        print(process.communicate()[0].decode())
    

    url=url.replace('http://','')
    url=url.replace('https://','')
    print("> URL = "+url+'\n')     # DEBUG
    threads=[]
    port = '0'
    ports = []
    services = []
    num_threads=values['-THREADS-']
    fname=strftime("%Y-%m-%d %H:%M:%S", gmtime())+"---"+ url.split('/')[0] +".ptsk"
    if not path.exists('Projects'):
        makedirs('Projects')
    f=open("Projects/"+fname, 'w', encoding='utf-8')
    diz={}
    diz["tabs"]=[]

    


    domain=url.split('/')[0]
    diz["host"]=domain
    diz["start_time"]=time()

    if ':' in domain:
        port = domain.split(':')[1]
        domain = domain.split(':')[0]
        
    if port!='0':
        val=sg.PopupYesNo("\nPenTasker will focus the scan on port "+port+". \n\nThis reduces the number of requests and the execution will be faster. \n\n\tAre you sure?",
                        title="Focus on port "+port+"?",button_color=('white', 'blue'))
        if val=="Yes":
            if isANint(port):
                ports.append(port)
        else:
            port='0'
    
    isAip=checkIP(domain)
    ip_addr=''
    if isAip:
        ip_addr=domain
    
    ##################################################################
    output, error=task_nslookup(values, domain)
    output=output.decode("utf-8")
    
    if error!=None:
        print("ERROR!")
    output, ip_addr, domain = clean_out_nslookup(output,isAip,ip_addr)
    data={
        'tool':'NsLookup',
        'output': [("General", output)]
    }
    diz["tabs"].append(data)

    if ": NXDOMA" in domain:
        domain=ip_addr

    if values['-tool0-']==True:                       # nslookup
        if verbose:
            print('\033[44;1m   NsLookup                                                                   \033[0m\n')
            print(output)

            print('\033[44;1m                                                                              \033[0m')
            print('------------------------------------------------------------------------------')
        else:
            print('\033[44;1m   NsLookup - completed                                                       \033[0m\n')
    else:
        if verbose:
            print('\033[47;1m\033[34;1m   NsLookup                                                                   \033[0m\n')
            print('\033[47;1m                                                                              \033[0m')
            print('------------------------------------------------------------------------------')
    ##################################################################
    ##################################################################
    if values['-tool1-']==True:                       # nmap
        output, ports, services=task_nmap(values, ip_addr, ports, services)
        diz["ports"]=ports
        diz["services"]=services

        if len(ports)==0:
            return
        #output=output.decode("utf-8")
        if error!=None:
            print("ERROR!")
        output = clean_out_nmap(output)
        data={
            'tool':'Nmap',
            'output': [("General", output)]
        }
        diz["tabs"].append(data)

        if verbose:
            print('\033[44;1m   Nmap                                                                       \033[0m\n')
            print(output)
            print('\033[44;1m                                                                              \033[0m')
            print('------------------------------------------------------------------------------')
        else:
            print('\033[44;1m   Nmap - completed                                                           \033[0m\n')
    else:
        if verbose:
            print('\033[47;1m\033[34;1m   Nmap                                                                       \033[0m\n')
            print('\033[47;1m                                                                              \033[0m')
            print('------------------------------------------------------------------------------')
    ##################################################################
    ##################################################################
    if values['-tool2-']==True:                       # nikto
        for i in range(0,len(services)):
            if "http" in services[i]:
                process = Thread(target=call_nikto, args=[values, ip_addr, ports[i], diz, verbose])  
                process.start()
                threads.append(process)

        
    else:
        if verbose:
            print('\033[47;1m\033[34;1m   Nikto                                                                      \033[0m\n')
            print('\033[47;1m                                                                              \033[0m')
            print('------------------------------------------------------------------------------')
    ##################################################################
    ##################################################################
    if values['-tool3-']==True:                       # vulscan
        for p in ports:
            process = Thread(target=call_vulscan, args=[values, ip_addr, p,diz, verbose])  
            process.start()
            threads.append(process)

        
    else:
        if verbose:
            print('\033[47;1m\033[34;1m   VulScan                                                                    \033[0m\n')
            print('\033[47;1m                                                                              \033[0m')
            print('------------------------------------------------------------------------------')
    ##################################################################
    ##################################################################
    if values['-tool4-']==True:                       # testssl.sh
        for i in range(0,len(services)):
            if "https" in services[i]:
                process = Thread(target=call_testssl, args=[values, ip_addr, ports[i], num_threads,diz, verbose])  
                process.start()
                threads.append(process)

        
    else:
        if verbose:
            print('\033[47;1m\033[34;1m   TestSSL.sh                                                                 \033[0m\n')
            print('\033[47;1m                                                                              \033[0m')
            print('------------------------------------------------------------------------------')
    ##################################################################
    ##################################################################
    if values['-tool5-']==True:                       # dirsearch

        for i in range(0,len(services)):
            if "http" in services[i]:
                process = Thread(target=call_dirsearch, args=[values, url, ports[i], num_threads,diz, verbose])  
                process.start()
                threads.append(process)

        
    else:
        if verbose:
            print('\033[47;1m\033[34;1m   DirSearch                                                                  \033[0m\n')
            print('\033[47;1m                                                                              \033[0m')
            print('------------------------------------------------------------------------------')
    ##################################################################
    ##################################################################
    if values['-tool7-']==True:                       # literesph

        for i in range(0,len(services)):
            if "http" in services[i]:
                process = Thread(target=call_literesph, args=[ip_addr,ports[i],diz,verbose])  
                process.start()
                threads.append(process)
        
    else:
        if verbose:
            print('\033[47;1m\033[34;1m   LiteRespH                                                                  \033[0m\n')
            print('\033[47;1m                                                                              \033[0m')
            print('------------------------------------------------------------------------------')
    ##################################################################
    ##################################################################
    if values['-tool8-']==True:                       # rhsecapi
        
        for i in range(0,len(services)):
            if "http" in services[i]:
                bashCommand = "curl  --connect-timeout 2 -s -I -i " + url + ":" + ports[i]
                process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
                lrh,err = process.communicate()
                softlist=[]

                out=lrh.decode().split('\n')
                for line in out:
                    if 'Server:'.lower() in line.lower() or 'Powered-By:'.lower() in line.lower():
                        soft=line.split(":")[1].strip()
                        regexp = re.compile(r'\d+(\.\d+)+')
                        if regexp.search(soft):
                            l=soft.split(" ")
                            for e in l:
                                if '/' in e:
                                    product=e.split("/")[0].strip()
                                    version=e.split("/")[1].strip()
                                    softlist.append((product,version))


                    elif 'AspNet:'.lower() in line.lower():
                        product="AspNet"
                        version==line.split(":")[1].strip()
                        softlist.append((product,version))
                    elif 'MicrosoftSharePointTeamServices:'.lower() in line.lower():
                        product="SharePoint"
                        version==line.split(":")[1].strip()
                        softlist.append((product,version))
                    else:
                        continue
                    
                if softlist!=[]:
                    for e in softlist:
                        process = Thread(target=call_rhsecapi, args=[e[0],e[1],diz,verbose])  
                        process.start()
                        threads.append(process)

        
    else:
        if verbose:
            print('\033[47;1m\033[34;1m   RHsecapi                                                                   \033[0m\n')
            print('\033[47;1m                                                                              \033[0m')
            print('------------------------------------------------------------------------------')
    ##################################################################
    ##################################################################
    if values['-tool9-']==True:                       # iis-shortname-scanner

        for i in range(0,len(services)):
            if "http" in services[i]:
                process = Thread(target=call_iis_ss, args=[ip_addr,ports[i],diz,verbose])  
                process.start()
                threads.append(process)
        
    else:
        if verbose:
            print('\033[47;1m\033[34;1m   IIS Shortname Scanner                                                      \033[0m\n')
            print('\033[47;1m                                                                              \033[0m')
            print('------------------------------------------------------------------------------')
    ##################################################################
    ##################################################################
    if values['-tool6-']==True:                       # legion

        for i in range(0,len(services)):
            if services[i].lower() in valid_protos.keys():
                if str(ports[i]) in valid_protos[services[i].lower()].defports:
                    protocol=valid_protos[services[i].lower()]
                    process = Thread(target=call_legion, args=[ip_addr,protocol,ports[i],diz,verbose])  
                    process.start()
                    threads.append(process)
        
    else:
        if verbose:
            print('\033[47;1m\033[34;1m   Legion                                                                     \033[0m\n')
            print('\033[47;1m                                                                              \033[0m')
            print('------------------------------------------------------------------------------')
    ##################################################################
    ##################################################################
    if values['-custom-']==True:                       # custom

        
        process = Thread(target=call_custom, args=[url,diz,verbose])  
        process.start()
        threads.append(process)

        
    else:
        if verbose:
            print('\033[47;1m\033[34;1m   Custom Scripts                                                             \033[0m\n')
            print('\033[47;1m                                                                              \033[0m')
            print('------------------------------------------------------------------------------')
    ##################################################################





    #~ END ~#
    print("\n\033[34;1mINFO:\033[0m Waiting for threads...\n")         # DEBUG
    for process in threads:
        process.join()
    diz["end_time"]=time()
    print('\033[42;1m\033[37;1m                                PT completed!                                 \033[0m\n')
    json.dump(diz, f, ensure_ascii=False, indent=4)

    return


def launch(values):
    verbose=values["-VERBOSE-"]
    printLogo()
    
    
    if "§" in values["-URL-"]:
        verbose=False
        urls=values["-URL-"].split("§")
        threads=[]
        for u in urls:
            process = Thread(target=tasks, args=[values, u, verbose])  
            process.start()
            threads.append(process)
        for process in threads:
            process.join()
        
    else:
        tasks(values,values["-URL-"],verbose)       # main function
    exit(0)


if len(sys.argv)>1:
    start_cli()
    exit(0)
# Event Loop to process "events" and get the "values" of the inputs
gui= Gui()
win=gui.window
help_message='You can insert the URL in any format including the following parameters:\n\n\t\t\thttp://IPorDomain:port/path\n\nThe only mandatory parameter is IPorDomain.\n\nExamples of available formats are:\n\n\t-\t192.168.0.17\n\n\t-\t192.168.0.17:8080\n\n\t-\texample.com\n\n\t-\texample.com:8080/login.php\n\n\nIn addition it is possible to pick a list of target from a file, by clicking the "Import list of targets" button or write more URL/IPs divided by the § character.\n\nP.S. the file should contain a target per line.\n' 
while True:
    event, values = gui.window.read()
    if event == sg.WIN_CLOSED or event == 'Cancel':	# if user closes window or clicks cancel
        win.close()
        exit(0)
    if event == "Select all":  
        for x in range(0,10):
            win.FindElement('-tool{}-'.format(x)).Update(True)
    if event == "Deselect all":  
        for x in range(2,10):
            win.FindElement('-tool{}-'.format(x)).Update(False)
    if event == "?":  
        sg.Popup(help_message,title="Help message")
    if event == '-LISTBTN-':  
        filename=sg.PopupGetFile(message="Pick a text file containing a target per line",title="Pick a text file")

        if filename == None:        # Check for file validity
            continue
        else:
            targets=open(filename).read()
            win.FindElement('-URL-').Update(targets.replace("\n","§")[:-1])
            win.FindElement('-VERBOSE-').Update(False)


    if event == '-BROWSE-':  
        filename=sg.PopupGetFile(message="Pick a PTSK file",file_types=(("PTSK Files", "*.ptsk"),))

        print(filename)     # DEBUG
        if filename == None:        # Check for file validity
            continue
        
        win.close()
        gui= Gui2(filename)
        win=gui.window
        while True:
            event, values = gui.window.read()
            if event == sg.WIN_CLOSED or event == 'Close':	# if user closes window or clicks cancel
                win.close()
                exit(0)
            if event == 'Generate\nReport':
                # name, host, ports, services, tabs
                # filename.split("/")[-1], data['host'], data['ports'], data['services'], data['tabs']
                try:
                    f=open(filename,'r', encoding='utf-8')
                except:
                    print("\033[31;1mERROR: File not found\033[0m")
                    exit()
                try:
                    data=json.loads(f.read())
                except:
                    print("\033[31;1mERROR: Invalid file\033[0m")
                    exit()
                reporter=Reporter(filename.split("/")[-1], data['host'], data['ports'], data['services'], data['tabs'])
                path=reporter.generate_report()
                sg.Popup("Report correctly generated. Its location is:\n"+path,title="Done!")
                
        break

        
        

    if event == "Launch":           # Get Parameters and Start tasks
        if values['-URL-']=='':
            win.FindElement('-ERROR-').Update(' '*3+'<-  Required!',text_color='red')
            continue
        # other controls on URL/IP
        win.hide()
        win.close()
        launch(values)


    
