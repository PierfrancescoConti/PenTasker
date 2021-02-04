from collections import Counter
import json
import subprocess
import datetime


	
def getSSAPNU(outsRH):
	lsoftware = []		# listaSoftware
	lcve=[]		# tot cves
	hcve=[]		# (host,listaCVE) - attenzione: gli host si ripetono
	for (host,outs) in outsRH:
		for ou in outs:
			lsoftware.append(ou[0])
			second=ou[1].split("\n")[1]
			cves=second.strip().replace(" ","").split(",")
			hcve.append((host,cves))
			for c in cves:
				lcve.append(c)
	
	if len(lsoftware)>0:
		print("The following software not updated were detected:")
		diz=dict((x,lsoftware.count(x)) for x in lsoftware)
		diz=dict(sorted(diz.items(), key=lambda item: item[1], reverse=True))
		for e in diz.keys():
			print(e+" was found "+str(diz[e])+" times")
		print()
		
	if len(lsoftware)>0:
		print("The following CVEs were detected:")
		diz=dict((x,lcve.count(x)) for x in lcve)
		diz.pop('', None)
		diz=dict(sorted(diz.items(), key=lambda item: item[1], reverse=True))
		i=0
		for e in diz.keys():
			if i==15:		# LIMIT first 15 CVEs
				break
			print(e+" was found "+str(diz[e])+" times inside the following hosts: ", end="")
			hostl=[]
			for (h,l) in hcve:
				if e in l:
					hostl.append(h)
			print(list(dict.fromkeys(hostl)))
			i+=1
		print()	
		i=0
		for e in diz.keys():
			if i==15:		# LIMIT first 15 CVEs
				break
			print(e+","+str(diz[e]))
			i+=1
		print()	
		
	return
	
def getRESPH(outsLRH):
	dizmiss={}	# dizionario {host, lista_missing_headers}
	miss=[]
	
	dizleak={}	# dizionario {host, lista_infoleaks}
	leaks=[]
	
	dizmet={}	# dizionario {host, lista metodi HTTP}
	methods=[]
	
	
	
	for (host,outs) in outsLRH:
		dizmiss[host]=[]
		dizleak[host]=[]
		dizmet[host]=[]
		for ou in outs:
			lo=ou[1].replace("\x1b","").split("\n")
			for line in lo:
				if "<!>" in line:
					dizmiss[host].append(line.strip())
					miss.append(line.strip())
				if "<?>" in line:
					dizleak[host].append(line.strip())
					leaks.append(line.strip())
					
				if "->" in line:
					for m in line.strip().replace("->","").split(","):
						dizmet[host].append(m.strip())
						methods.append(m.strip())
				
	if len(miss)>0:
		diz=dict((x,miss.count(x)) for x in miss)
		diz=dict(sorted(diz.items(), key=lambda item: item[1], reverse=True))
		print("The following missing response headers were detected:")
		for e in diz.keys():
			print(e+" was found "+str(diz[e])+" times about the following hosts: ", end="")
			hostl=[]
			for m in dizmiss.keys():
				if e in dizmiss[m]:
					hostl.append(m)
			print(hostl)
		print()
		
		for e in diz.keys():
			print(e+","+str(diz[e]))
		print()	
		
	if len(leaks)>0:
		diz=dict((x,leaks.count(x)) for x in leaks)
		diz=dict(sorted(diz.items(), key=lambda item: item[1], reverse=True))
		print("The following info leaks were detected:")
		for e in diz.keys():
			print(e+" "+str(diz[e])+" times about the following hosts: ", end="")
			hostl=[]
			for m in dizleak.keys():
				if e in dizleak[m]:
					hostl.append(m)
			print(hostl)
		print()
		
		for e in diz.keys():
			print(e.replace("<?> Found  ","").replace("  field","")+","+str(diz[e]))
		print()	
		
	if len(methods)>0:
		diz=dict((x,methods.count(x)) for x in methods)
		diz=dict(sorted(diz.items(), key=lambda item: item[1], reverse=True))
		print("The following HTTP methods were detected:")
		for e in diz.keys():
			print(e+" was found "+str(diz[e])+" times about the following hosts: ", end="")
			hostl=[]
			for m in dizmet.keys():
				if e in dizmet[m]:
					hostl.append(m)
			print(hostl)
		print()
		
		for e in diz.keys():
			print(e.replace("<!> Missing  ","").replace("  field","")+","+str(diz[e]))
		print()	
	
	return


def getIIS(outsIIS):
	iis=[]
	
	for (host,outs) in outsIIS:
		for ou in outs:
			lo=ou[1].replace("\x1b","").split("\n")
			if "_ Result: Vulnerable!" in lo and host not in iis:
				iis.append(host)
				
	if len(iis)>0:
		print("It was found that the following hosts are vulnerable to Tilde Enumeration (8.3): ")	
		print(iis)
		print()
	return
	
def getPorts(outPorts):
	dizports={}
	lports=[]
	
	for (host,ports) in outPorts:
		dizports[host]=[]
		for p in ports:
			lports.append(p)
			dizports[host].append(p)

				
	if len(lports)>0:
		diz=dict((x,lports.count(x)) for x in lports)
		diz=dict(sorted(diz.items(), key=lambda item: item[1], reverse=True))
		print("Open ports detected:")
		for e in diz.keys():
			print(e+" ports were found "+str(diz[e])+" times about the following hosts: ", end="")
			hostl=[]
			for m in dizports.keys():
				if e in dizports[m]:
					hostl.append(m)
			print(hostl)
		print()
		
		for e in diz.keys():
			print(e+","+str(diz[e]))
		print()	
	
def getServ(outServ):
	dizserv={}
	lserv=[]
	
	for (host,serv) in outServ:
		dizserv[host]=[]
		for s in serv:
			lserv.append(s)
			dizserv[host].append(s)
				
	if len(lserv)>0:
		diz=dict((x,lserv.count(x)) for x in lserv)
		diz=dict(sorted(diz.items(), key=lambda item: item[1], reverse=True))
		print("Services detected:")
		for e in diz.keys():
			print(e+" services were found "+str(diz[e])+" times about the following hosts: ", end="")
			hostl=[]
			for m in dizserv.keys():
				if e in dizserv[m]:
					hostl.append(m)
			print(hostl)
		print()
		
		for e in diz.keys():
			print(e+","+str(diz[e]))
		print()	
	
def getDurata(outsTime):
	m=0
	tot=0
	i=0
	for (host,time) in outsTime:
		if int(time)>m:
			m=int(time)
		tot+=int(time)
		i+=1
		print("The scan on the host "+host+" lasted -> "+str(datetime.timedelta(seconds=int(time)))+" (hh:mm:ss)")
	print()
	print("Average: "+str(datetime.timedelta(seconds=int(tot/i))))
	print("Max: "+str(datetime.timedelta(seconds=int(m))))
	print()




bashCommand = "ls"
process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
o,e = process.communicate()
onlyfiles = [f for f in o.decode().split("\n") if ".ptsk" in f]
allouts=[]
outsRH=[]
outsLRH=[]
outsIIS=[]
outsTime=[]
outPorts=[]
outServ=[]

# get RHsecapi outs
for fn in onlyfiles:
	print(fn.split("---")[1][0:-5])   # DEBUG
	f=open(fn,'r', encoding='utf-8')
	data=json.loads(f.read())
	allouts.append(data)
	outPorts.append((data['host'],data['ports']))
	outServ.append((data['host'],data['services']))
	outsTime.append((data['host'],data['end_time']-data["start_time"]))
	
	for X in data['tabs']:
		if X['tool'].strip().lower() == 'rhsecapi':
			outsRH.append((data['host'],X['output']))	# tupla (host,outs) dove outs[i][0] è 'nginx' e outs[i][1] è l'output relativo a 'nginx'
		if X['tool'].strip().lower() == 'literesph':
			outsLRH.append((data['host'],X['output']))	# outs dove outs[i][0] è la porta e outs[i][1] è l'output relativo a tale porta
		if 'iis' in X['tool'].strip().lower():
			outsIIS.append((data['host'],X['output']))
			
print()
getPorts(outPorts)
getServ(outServ)
getSSAPNU(outsRH)
getRESPH(outsLRH)
getIIS(outsIIS)

getDurata(outsTime)
