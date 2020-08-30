from os import system, name 
import subprocess
import PySimpleGUI as sg
from GUI import Gui
from threading import Thread
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



# Thread Calls
def call_nikto(values, ip_addr):
    output, error=task_nikto(values, ip_addr)
    output=output.decode()
    if error!=None:
        print("ERROR!")
    output = clean_out_nikto(output)
    print('\033[44;1m   Nikto                                                                      \033[0m\n')
    print(output)
    print('\033[44;1m                                                                              \033[0m')
    print('------------------------------------------------------------------------------')

def call_vulscan(values, ip_addr, ports):
    output, error=task_vulscan(values, ip_addr, ports)
    output=output.decode()
    if error!=None:
        print("ERROR!")
    output = clean_out_vulscan(output)
    print('\033[44;1m   VulScan                                                                    \033[0m\n')
    print(output)
    print('\033[44;1m                                                                              \033[0m')
    print('------------------------------------------------------------------------------')

def call_testssl(values, ip_addr, num_threads):
    output, error=task_testssl(values, ip_addr, num_threads)
    output=output.decode()
    if error!=None:
        print("ERROR!")
    output = clean_out_testssl(output)      # comment this line to obtain the real output (to add inside tabs)
    print('\033[44;1m   TestSSL.sh                                                                 \033[0m\n')
    print(output[:-3])
    print('\033[44;1m                                                                              \033[0m')
    print('------------------------------------------------------------------------------')

def call_dirsearch(values, url, num_threads):
    output, error=task_dirsearch(values, url, num_threads)
    output=output.decode()
    if error!=None:
        print("ERROR!")
    output = clean_out_dirsearch(output)
    print('\033[44;1m   DirSearch                                                                  \033[0m\n')
    print(output)
    print('\033[44;1m                                                                              \033[0m')
    print('------------------------------------------------------------------------------')




# Tasks
def task_nslookup(values, url):
    bashCommand = "nslookup "+url
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    return process.communicate()

def task_nmap(values, ip_addr, ports):
    if values['-RADIO1-']:          # Fast
        if len(ports)==0:
            bashCommand = "nmap -T" + str(int(values['-RISK-'])) + " "+ip_addr
            process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
            output, error = process.communicate()
            output=output.decode("UTF-8")
            ports = get_ports(output)

        if len(ports)==0:
            print("\033[31;1mNo ports detected... Maybe the host is down.\033[0m ")
        else:
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
        if len(ports)==0:
            print("\033[33;1mNo ports detected... Maybe the host is down.\033[0m")
        else:
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



def task_nikto(values, ip_addr, port):
    if port=='0':
        bashCommand = "nikto -h "+ip_addr
    else:
        bashCommand = "nikto -p "+port+" -h "+ip_addr
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    return process.communicate()

def task_vulscan(values, ip_addr, ports):
    bashCommand = "nmap -T" + str(int(values['-RISK-'])) + " -sV --script=tools/vulscan/vulscan.nse -p "
    for p in ports:
        bashCommand+=p+','
    bashCommand=bashCommand[:-1]+' '+ip_addr
    print(bashCommand)      # DEBUG
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    return process.communicate()

def task_dirsearch(values, url, num_threads):
    bashCommand = "python3 tools/dirsearch/dirsearch.py -u " + url + " -e ,html,txt,php,aspx -t " + str(num_threads)
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    return process.communicate()

def task_testssl(values, ip_addr, num_threads):
    bashCommand = "./tools/testssl.sh/testssl.sh " + ip_addr
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
    for line in out:
        if 'Extensions:' in line:
            x=True
            ret+=line + '\n'
        elif 'Error Log:' in line or 'Output File:' in line or '] 400 - ' in line or '] 401 - ' in line or '] 402 - ' in line or '] 403 - ' in line or '] 404 - ' in line or x==False:
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
def tasks(values):
    printLogo()
    url=values['-URL-']
    url=url.replace('http://','')
    url=url.replace('https://','')
    print("> URL = "+url+'\n')     # DEBUG
    threads=[]
    port = '0'
    ports = []
    num_threads=values['-THREADS-']

    domain=url.split('/')[0]
    if ':' in domain:
        port = domain.split(':')[1]
        domain = domain.split(':')[0]
        
    print(domain+' - '+port)    # DEBUG
    if port!='0':
        val=sg.PopupYesNo("\nPenTasker will focus the scan on port "+port+". \n\nThis reduces the number of requests and the execution will be faster. \n\n\tAre you sure?",
                        title="Focus on port "+port+"?",button_color=('white', 'blue'))
        if val=="Yes":
            if isANint(port):
                ports.append(port)
            print(val)     # DEBUG
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
        output, ports=task_nmap(values, ip_addr, ports)
        if len(ports)==0:
            return
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
        process = Thread(target=call_nikto, args=[values, ip_addr])  
        process.start()
        threads.append(process)

        
    else:
        print('\033[47;1m\033[34;1m   Nikto                                                                      \033[0m\n')
        print('\033[47;1m                                                                              \033[0m')
        print('------------------------------------------------------------------------------')
    ##################################################################
    ##################################################################
    if values['-tool3-']==True:                       # vulscan
        process = Thread(target=call_vulscan, args=[values, ip_addr, ports])  
        process.start()
        threads.append(process)

        
    else:
        print('\033[47;1m\033[34;1m   VulScan                                                                    \033[0m\n')
        print('\033[47;1m                                                                              \033[0m')
        print('------------------------------------------------------------------------------')
    ##################################################################
    ##################################################################
    if values['-tool4-']==True:                       # testssl.sh

        process = Thread(target=call_testssl, args=[values, ip_addr, num_threads])  
        process.start()
        threads.append(process)

        
    else:
        print('\033[47;1m\033[34;1m   TestSSL.sh                                                                 \033[0m\n')
        print('\033[47;1m                                                                              \033[0m')
        print('------------------------------------------------------------------------------')
    ##################################################################
    ##################################################################
    if values['-tool5-']==True:                       # dirsearch

        
        process = Thread(target=call_dirsearch, args=[values, url, num_threads])  
        process.start()
        threads.append(process)

        
    else:
        print('\033[47;1m\033[34;1m   DirSearch                                                                  \033[0m\n')
        print('\033[47;1m                                                                              \033[0m')
        print('------------------------------------------------------------------------------')
    ##################################################################





    #~ END ~#
    print("Waiting for threads...")         # DEBUG
    for process in threads:
        process.join()
    print('\033[42;1m\033[37;1m                                PT completed!                                 \033[0m\n')
    return






# Event Loop to process "events" and get the "values" of the inputs
gui= Gui()
win=gui.window
help_message='You can insert the URL in any format including the following parameters:\n\n\t\t\thttp://IPorDomain:port/path\n\nThe only mandatory parameter is IPorDomain.\n\nExamples of available formats are:\n\n\t-\t192.168.0.17\n\n\t-\t192.168.0.17:8080\n\n\t-\texample.com\n\n\t-\texample.com:8080/login.php' 
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
    if event == "?":  
        sg.Popup(help_message)

    if event == "Launch":           # Get Parameters and Start tasks
        if values['-URL-']=='':
            win.FindElement('-ERROR-').Update(' '*3+'<-  Required!',text_color='red')
            continue
        # other controls on URL/IP
        win.close()
        
        tasks(values)       # main function

    



