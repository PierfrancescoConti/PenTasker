import PySimpleGUI as sg
import json


######## bash colors ########
# COLOR_RESET  "\033[0m"    #
# BOLD         "\033[1m"    #
# BLACK_TEXT   "\033[30;1m" #
# RED_TEXT     "\033[31;1m" #
# GREEN_TEXT   "\033[32;1m" #
# YELLOW_TEXT  "\033[33;1m" #
# BLUE_TEXT    "\033[34;1m" #
# MAGENTA_TEXT "\033[35;1m" #
# CYAN_TEXT    "\033[36;1m" #
# WHITE_TEXT   "\033[37;1m" #
#############################


class Gui:
    def __init__(self):
        help_b64 = b'iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAABmJLR0QA/wD/AP+gvaeTAAAAB3RJTUUH5AcaCTUSktwQrgAABF9JREFUOMt9VVtoVFcUXXufc+c6GTOWiUlmRqPVmMRgqSRpK9j6Aq2pFkTbn4JCm0IhYNC+RAT729IWURQUpFZQ8KugViEgRZuixTYxVSqah7UdTWZimMTmNbkz95zdj3FMGkvX99lr7bXX3hzatOccamqqEAwWIZ1Oc7i4GEcOHrSZxANnS3NzXTwWrVdaxwDA+H6yP5m6ce7Y0c5gRUVu5+7dPDI6ipKSEjuRmUB3Vw+o5XgnSiKz0Xv3Pp/at0GIiN/96to70Wh5S2h2qE5r7TAzAMBaC9/3c+Pj452p1MDhk5+sPCMidsfnl2hJzSKbHhoD7TnZhb7+JF/64bJdUrk4umLFK9+Wls5tdF1XAJCIWAIEAAQgImIA4nkeDQ4Otl6//ut7vb1/pDasX8vz4jGrwlWN3PZju31+UTy+evWq1lgs+qrW2jfGEAACQJ4v7FthxSARgbVWHMcxxcXF1ZFI5PXHw8Pn29u7RnTAYRIRAiAfnbh7Yd68+GYRyYnAYQZ8AxABCyIaAJAY8iECaAVYCxBTjgCnr6//4oGmpW8CINp14g7+Tg9tr66pPuW6rm+t1QTACOBqwlsvFSGgCACQNYLv2ifg+QL1ZA7M7Huep7u7unfMKYmc5kNNtRyNRZtd14UxhoF8V15O8Fq1i0xWcLxtFMfbRjGZE6yqduHlBJTXgDGGXddFNBZtPtRUy7x1f2tDKBSqzxMRA3hqq7RY4eaDLAoiHX9mEQkpaPUkpXwNAUAoFKrbur+1nsuj5fVa61kiYjENTITbD7MYyVgEFCGbE1SWaYx7Nj/bqackIlZrHYxGyxvYUSrOzBCRgigEgGKgM5FFeswiawTLKwJYFg/gWq8HR091mHckwsxQSsUY/4NZDsEKUDJbYcOyInz/2wQejRoEFEHkv2s4Z/x+a+3TWczEZE5QvyCAxJCP2/1ZFAXyItNBRGSthTGmnwdSjzp8388UApmOgvXRSYu+YR8B/SwZACEi9n0/k0oN3CAAvPf0vZ9KS0tXGmPsTGICMJHLsxQ5hJl8ImKVUjw4OHj1i+2Vq3nXiTs2lUwd9TwPSql/JU0EeL5gfW0Q62uD8Pyp/StAKWU9z0MqmTq265s79pnTA5ATEWf6gq9dGgQAXLmbgetMBUJEOQBOX1/fxQNNtfnTe+PTC/zL9Vt20eKy2Lp1a1rLy8teJCLfGMMF+1k/zxDQNN2mFRE9MDBw68qVtsb79waSL69YzmrbB59JedlzfKPz5ujY2NjZOeHwC+4st9pxnELy1lFktSIBEZiZmBme56lkMtV69drPb/f23k9t3LiGqyoXWlW/+X3Mr5grkXCYL365bayxoexMRcPWHmaaT0RlALQAbEXYGEOe5+WGhx93JBKJvcd21u972HF27PeU4aqlC+3IeAa0ac951FQvQbAoiHR6iMPhYhz++oCdTPylt+xsqYvHog0zvoCOc0cOd7oLFvotH3/IIyOFLyCDnu4e/APBGx1vAKSNpgAAACV0RVh0ZGF0ZTpjcmVhdGUAMjAyMC0wNy0yNlQwOTo1MzoxOC0wNzowMGgxnG4AAAAldEVYdGRhdGU6bW9kaWZ5ADIwMjAtMDctMjZUMDk6NTM6MTgtMDc6MDAZbCTSAAAAAElFTkSuQmCC'        
        sg.theme('DarkBlue')
        sg.SetOptions(element_padding=((10,10),9))
        col1 = [[sg.Text('Research:', font=('Helvetica',13,'bold'))],
               [sg.Text('->'), sg.Checkbox(' NsLookup', size=(15,1),default=True, disabled=True, key='-tool0-')],
               [sg.Text('->'),sg.Checkbox(' Nmap', size=(15,1),default=True, disabled=True, key='-tool1-')],
               [sg.Text('->'),sg.Checkbox(' Nikto', size=(15,1),default=True, key='-tool2-')],
               [sg.Text('->'),sg.Checkbox(' VulScan', size=(15,1),default=True, key='-tool3-')],
               [sg.Text('->'),sg.Checkbox(' TestSSL.sh', size=(15,1),default=True, key='-tool4-')],
               [sg.Text('->'),sg.Checkbox(' LiteRespH', size=(9,1),default=True, key='-tool7-')],
               ]

        col2 = [[sg.Text('Exploitation:', font=('Helvetica',13,'bold'))],
               [sg.Text('->'),sg.Checkbox(' DirSearch', size=(9,1),default=True, key='-tool5-')],
               [sg.Text('->'),sg.Checkbox(' Sqlmap', size=(9,1),default=True, key='-tool6-')],
               [sg.Text('->'),sg.Checkbox(' RHsecapi', size=(9,1),default=True, key='-tool8-')],
               [sg.Text('->'),sg.Checkbox(' IIS SS', size=(9,1),default=True, key='-tool9-')],
               [sg.Text('->'),sg.Checkbox(' Custom', size=(9,1), key='-custom-')]
               ]


        col3 = [[sg.Text('Attributes:', font=('Helvetica',13,'bold'))],
               [sg.Text('Risk Level:      '), sg.Slider(range=(1, 5), orientation='h', size=(22, 15), default_value=4, key='-RISK-')],
               [sg.Text('Max Threads: '), sg.Spin(values=[i for i in range(1, 30)], initial_value=5, size=(6, 1), key='-THREADS-')],
               [sg.Text('Scan Mode: '), sg.Radio('Fast', 'rapid', default=True, size=(12, 1), key='-RADIO1-'), sg.Radio('Complete', 'rapid', size=(12, 1), key='-RADIO2-')], 
               ]

        layout = [  
                [sg.Text('\t      PenTasker', justification='center', size=(100, 1), font=('Helvetica',16,'bold')), sg.Text("",visible=False, key="-PKTS-"), sg.Button('Import\nProject', button_color=('white', '#3971c6'), size=(10,2), key='-BROWSE-')], # ,file_types=(("PTSK Files", "*.ptsk"),), 
                [sg.Frame('',[
                    [sg.Button('Select all'), sg.Button('Deselect all')],
                    [sg.Text('')],
                    [sg.Text(' '*25), sg.Text('URL / IP: ', font=('Helvetica',13,'bold')), sg.Input('', size=(40,1), justification='center', key='-URL-'), sg.Button('Import list\nof targets', button_color=('white', '#3971c6'), size=(10,2), key='-LISTBTN-'),sg.Button('', image_data=help_b64,button_color=(sg.theme_background_color(),sg.theme_background_color()),border_width=0, key='?'),sg.Text(' '*25, key='-ERROR-')],
                    [sg.Column(col1,key='-col1-'), sg.Column(col2,key='-col2-'), sg.VerticalSeparator(), sg.Column(col3,key='-col3-')], 
                    [sg.Text('')] 
                    ])
                ],

                [sg.Button('Launch', button_color=('white', 'springgreen4'), size=(30,2), font='Helvetica 14'), sg.Button('Cancel',size=(30,2), font='Helvetica 14')] 
                ]
        self.window=sg.Window('PenTasker   -   v. 0.1', layout, element_justification='c', font=("Helvetica", 12),icon='Images/PenTasker-icon.png')




class Gui2():



    def __init__(self,filename):
        
        def no_colors(output):
            out = output.replace("[m","")
            out = out.replace("[0m","")
            out = out.replace("[1m","")
            out = out.replace("[7m","")
            out = out.replace("[33m","")
            out = out.replace("[35m","")
            out = out.replace("[36m","")
            out = out.replace("\\x0D","")
            for i in range(0,100):
                out = out.replace("["+str(i)+";1m","")
                out = out.replace("["+str(i)+";0m","")
                out = out.replace("[0;"+str(i)+"m","")
                out = out.replace("[1;"+str(i)+"m","")
            return out

        help_b64 = b'iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAABmJLR0QA/wD/AP+gvaeTAAAAB3RJTUUH5AcaCTUSktwQrgAABF9JREFUOMt9VVtoVFcUXXufc+c6GTOWiUlmRqPVmMRgqSRpK9j6Aq2pFkTbn4JCm0IhYNC+RAT729IWURQUpFZQ8KugViEgRZuixTYxVSqah7UdTWZimMTmNbkz95zdj3FMGkvX99lr7bXX3hzatOccamqqEAwWIZ1Oc7i4GEcOHrSZxANnS3NzXTwWrVdaxwDA+H6yP5m6ce7Y0c5gRUVu5+7dPDI6ipKSEjuRmUB3Vw+o5XgnSiKz0Xv3Pp/at0GIiN/96to70Wh5S2h2qE5r7TAzAMBaC9/3c+Pj452p1MDhk5+sPCMidsfnl2hJzSKbHhoD7TnZhb7+JF/64bJdUrk4umLFK9+Wls5tdF1XAJCIWAIEAAQgImIA4nkeDQ4Otl6//ut7vb1/pDasX8vz4jGrwlWN3PZju31+UTy+evWq1lgs+qrW2jfGEAACQJ4v7FthxSARgbVWHMcxxcXF1ZFI5PXHw8Pn29u7RnTAYRIRAiAfnbh7Yd68+GYRyYnAYQZ8AxABCyIaAJAY8iECaAVYCxBTjgCnr6//4oGmpW8CINp14g7+Tg9tr66pPuW6rm+t1QTACOBqwlsvFSGgCACQNYLv2ifg+QL1ZA7M7Huep7u7unfMKYmc5kNNtRyNRZtd14UxhoF8V15O8Fq1i0xWcLxtFMfbRjGZE6yqduHlBJTXgDGGXddFNBZtPtRUy7x1f2tDKBSqzxMRA3hqq7RY4eaDLAoiHX9mEQkpaPUkpXwNAUAoFKrbur+1nsuj5fVa61kiYjENTITbD7MYyVgEFCGbE1SWaYx7Nj/bqackIlZrHYxGyxvYUSrOzBCRgigEgGKgM5FFeswiawTLKwJYFg/gWq8HR091mHckwsxQSsUY/4NZDsEKUDJbYcOyInz/2wQejRoEFEHkv2s4Z/x+a+3TWczEZE5QvyCAxJCP2/1ZFAXyItNBRGSthTGmnwdSjzp8388UApmOgvXRSYu+YR8B/SwZACEi9n0/k0oN3CAAvPf0vZ9KS0tXGmPsTGICMJHLsxQ5hJl8ImKVUjw4OHj1i+2Vq3nXiTs2lUwd9TwPSql/JU0EeL5gfW0Q62uD8Pyp/StAKWU9z0MqmTq265s79pnTA5ATEWf6gq9dGgQAXLmbgetMBUJEOQBOX1/fxQNNtfnTe+PTC/zL9Vt20eKy2Lp1a1rLy8teJCLfGMMF+1k/zxDQNN2mFRE9MDBw68qVtsb79waSL69YzmrbB59JedlzfKPz5ujY2NjZOeHwC+4st9pxnELy1lFktSIBEZiZmBme56lkMtV69drPb/f23k9t3LiGqyoXWlW/+X3Mr5grkXCYL365bayxoexMRcPWHmaaT0RlALQAbEXYGEOe5+WGhx93JBKJvcd21u972HF27PeU4aqlC+3IeAa0ac951FQvQbAoiHR6iMPhYhz++oCdTPylt+xsqYvHog0zvoCOc0cOd7oLFvotH3/IIyOFLyCDnu4e/APBGx1vAKSNpgAAACV0RVh0ZGF0ZTpjcmVhdGUAMjAyMC0wNy0yNlQwOTo1MzoxOC0wNzowMGgxnG4AAAAldEVYdGRhdGU6bW9kaWZ5ADIwMjAtMDctMjZUMDk6NTM6MTgtMDc6MDAZbCTSAAAAAElFTkSuQmCC'        
        sg.theme('DarkBlue')
        sg.SetOptions(element_padding=((10,10),9))
        f=open(filename,'r', encoding='utf-8')
        
        data=json.loads(f.read())

        tabsX = []
        for X in data['tabs']:
            tabs = []
            tabname=X['tool']
            for Y in X['output']: # port=Y[0] , output=Y[1] 
                port=Y[0]
                out=no_colors(Y[1])
                tab=sg.Tab(layout=[[sg.Multiline("\n  "+out.replace("\n","\n  "),background_color="white",text_color="black",pad=(0,0), size=(190,45), disabled=True)],],title=port, background_color="white", pad=(20,20))
                tabs.append(tab)
            tabX=sg.Tab(layout=[[sg.TabGroup([ tabs ])],],title=tabname, pad=(20,20))
            tabsX.append(tabX)
        

               
        layout2 = [[sg.TabGroup([ tabsX ])],
              [sg.Button('Close')]]

        self.window=sg.Window('PTSK Project', layout2, element_justification='c', font=("Helvetica", 12),icon='Images/PenTasker-icon.png')

