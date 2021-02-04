# PenTasker
Automated Pentesting scanner composed by some of the most used tools in this job. It is possible to extend it through custom tasks.<br>
The goal of this project is to optimize the assessment and reporting phases' time.<hr>

### Installation
```
git clone https://github.com/PierfrancescoConti/PenTasker.git
```
<hr>

### Requirements
Because of LiteRespH tool, `curl` is required.<br>
Tools like `nmap` and `nslookup` must be installed on the system.<br>
Install requirements using the following command:
```
python3 -m pip install -r requirements.txt
```

<br>

Setup tools:
```
chmod +x setup.sh
./setup.sh      # hint: don't execute this as root
```
<hr>


### Execution
Execute this and a GUI will prompt out:
```
python3 pentasker.py
```
<br>

![Screenshot](main-GUI.png) <br><br>

Choose the tools you want to execute (recommended all) and setup the execution attributes.<br>
After this start the tasks and go take a coffee! ☕️
<hr>

### Import Projects
After an execution, a file PTSK is generated. It contains the relative scan's results.<br>
It is possible to review these results, by choosing the file through the Import Project functionality.<br><br>
![Screenshot](Out-display.png) <br><br>
<hr>


### Screenshot

![Screenshot](Overview.png) 
<hr>


