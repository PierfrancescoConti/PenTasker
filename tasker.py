from os import system, name 
import subprocess
import PySimpleGUI as sg
from GUI import Gui
import re 


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
    out=output0.split('\n')
    for line in out:
        p=line.split('/')[0]
        if isANint(p):
            ports.append(p)
    return ports





# Tasks
def task_nslookup(values):
    bashCommand = "nslookup "+values['-URL-']
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    return process.communicate()

def task_nmap(values, ip_addr):
    if values['-RADIO1-']:          # Fast
        bashCommand = "nmap -T" + str(int(values['-RISK-'])) + " "+ip_addr
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()
        output=output.decode("UTF-8")
        ports = get_ports(output)
        ######## RILANCIARE IL COMANDO CON -A #########
        bashCommand = "nmap -T" + str(int(values['-RISK-'])) + " -A -p "
        for p in ports:
            bashCommand+=p+','
        bashCommand=bashCommand[:-1]+' '+ip_addr
        print(bashCommand)      # DEBUG
        print('\033[32;1mDetected ports:\033[0m '+ ', '.join(ports) +'\n')
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        output, error =  process.communicate()
        output=output.decode("UTF-8")
        
    else:
        bashCommand = "nmap -T" + str(int(values['-RISK-'])) + " -p- "+ip_addr
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        output, error =  process.communicate()
        output=output.decode("UTF-8")
        ports = get_ports(output)
        ######## RILANCIARE IL COMANDO CON -A #########
        bashCommand = "nmap -T" + str(int(values['-RISK-'])) + " -A -p "
        print(bashCommand)      # DEBUG
        for p in ports:
            bashCommand+=p+','
        bashCommand=bashCommand[:-1]+' '+ip_addr
        print('\033[32;1mDetected ports:\033[0m '+ ', '.join(ports) +'\n')
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        output, error =  process.communicate()
        output=output.decode("UTF-8")

    return output, ports

def task_nikto(values, ip_addr):
    bashCommand = "nikto -h "+ip_addr
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    return process.communicate()



# Cleaners
def clean_out_nslookup(output,isAip, ip_addr):
    if isAip:
        out=output.split('\n\n')
        name=out[0].split('\n')[-1]
        domain=name[name.find('name = ')+7:-1]
        #print(domain)       # DEBUG
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
    return output.split('\n\n')[1]+'\n'

def clean_out_nikto(output):
    out=output.split('\n')
    ret=''
    for line in out:
        if 'Nikto' in line or 'Start Time:' in line or 'End Time:' in line or 'items checked:' in line or 'host(s) tested' in line:
            continue
        else:
            ret+=line + '\n'
    return ret











# Tasks Caller
def tasks(values):
    printLogo()
    url=values['-URL-']
    url=url.replace('http://','')
    url=url.replace('https://','')
    print("> URL = "+url+'\n')     # DEBUG

    domain=url.split('/')[0]
    isAip=checkIP(domain)
    ip_addr=''
    if isAip:
        ip_addr=domain
    
    ##################################################################
    output, error=task_nslookup(values)
    output=output.decode("utf-8")
    
    if error!=None:
        print("ERROR!")
    output, ip_addr, domain = clean_out_nslookup(output,isAip,ip_addr)
    #print(domain)       # DEBUG
    if ": NXDOMA" in domain:
        domain=ip_addr
    if values['-tool0-']==True:                       # nslookup
        print('\033[44;1m   NsLookup                                                                   \033[0m\n')
        print(output)
        
        print('\033[44;1m                                                                              \033[0m')
        print('------------------------------------------------------------------------------')
    else:
        print('\033[47;1m\033[34;1m   NsLookup                                                                   \033[0m\n')
        print('\033[47;1m                                                                              \033[0m')
        print('------------------------------------------------------------------------------')
    ##################################################################
    ##################################################################
    if values['-tool1-']==True:                       # nmap
        output, ports=task_nmap(values, ip_addr)
        #output=output.decode("utf-8")
        if error!=None:
            print("ERROR!")
        output = clean_out_nmap(output)
        print('\033[44;1m   Nmap                                                                       \033[0m\n')
        print(output)
        print('\033[44;1m                                                                              \033[0m')
        print('------------------------------------------------------------------------------')
    else:
        print('\033[47;1m\033[34;1m   Nmap                                                                       \033[0m\n')
        print('\033[47;1m                                                                              \033[0m')
        print('------------------------------------------------------------------------------')
    ##################################################################
    ##################################################################
    if values['-tool2-']==True:                       # nikto
        output, ports=task_nikto(values, ip_addr)
        output=output.decode()
        if error!=None:
            print("ERROR!")
        output = clean_out_nikto(output)
        print('\033[44;1m   Nikto                                                                      \033[0m\n')
        print(output)
        print('\033[44;1m                                                                              \033[0m')
        print('------------------------------------------------------------------------------')
    else:
        print('\033[47;1m\033[34;1m   Nikto                                                                      \033[0m\n')
        print('\033[47;1m                                                                              \033[0m')
        print('------------------------------------------------------------------------------')
    ##################################################################






    #~ END ~#
    print('\033[42;1m\033[37;1m                                PT completed!                                 \033[0m\n')
    return






# Event Loop to process "events" and get the "values" of the inputs
gui= Gui()
win=gui.window
while True:
    event, values = gui.window.read()
    if event == sg.WIN_CLOSED or event == 'Cancel':	# if user closes window or clicks cancel
        win.close()
        break
    if event == "Select all":  
        for x in range(0,9):
            win.FindElement('-tool{}-'.format(x)).Update(True)
    if event == "Deselect all":  
        for x in range(0,9):
            win.FindElement('-tool{}-'.format(x)).Update(False)

    if event == "Launch":           # Get Parameters and Start tasks
        if values['-URL-']=='':
            win.FindElement('-ERROR-').Update(' '*3+'<-  Required!',text_color='red')
            continue
        # other controls on URL/IP
        win.close()
        
        tasks(values)       # main function

    



