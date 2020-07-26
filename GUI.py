import PySimpleGUI as sg

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
        sg.theme('DarkBlue')
        sg.SetOptions(element_padding=((10,10),9))
        col1 = [
               [sg.Checkbox(' NsLookup', size=(15,1),default=True, key='-tool0-')],
               [sg.Checkbox(' Nmap', size=(15,1),default=True, key='-tool1-')],
               [sg.Checkbox(' Nikto', size=(15,1),default=True, key='-tool2-')],
               [sg.Checkbox(' Sqlmap', size=(15,1),default=True, key='-tool3-')],
               [sg.Checkbox(' TestSSL.sh', size=(15,1),default=True, key='-tool4-')]
               ]

        col2 = [
               [sg.Checkbox(' DirSearch', size=(9,1),default=True, key='-tool5-')],
               [sg.Checkbox(' Tool6', size=(9,1),default=True, key='-tool6-')],
               [sg.Checkbox(' Tool7', size=(9,1),default=True, key='-tool7-')],
               [sg.Checkbox(' Tool8', size=(9,1),default=True, key='-tool8-')],
               [sg.Checkbox(' Custom', size=(9,1), key='-custom-')]
               ]


        col3 = [
               [sg.Text('Risk Level:      '), sg.Slider(range=(1, 5), orientation='h', size=(22, 15), default_value=4, key='-RISK-')],
               [sg.Text('Max Threads: '), sg.Spin(values=[i for i in range(1, 30)], initial_value=5, size=(6, 1))],
               [sg.Text('Scan Mode: '), sg.Radio('Fast', 'rapid', default=True, size=(12, 1), key='-RADIO1-'), sg.Radio('Complete', 'rapid', size=(12, 1), key='-RADIO2-')], 
               ]

        layout = [  
                [sg.Text('PenTasker', justification='center', size=(100, 1), font='Helvetica 14')],
                [sg.Frame('',[
                    [sg.Button('Select all'), sg.Button('Deselect all')],
                    [sg.Text('')],
                    [sg.Text(' '*25), sg.Text('URL / IP: '), sg.Input('', size=(40,1), justification='center', key='-URL-'),sg.Text(' '*25, key='-ERROR-')],
                    [sg.Column(col1,key='-col1-'), sg.Column(col2,key='-col2-'), sg.VerticalSeparator(), sg.Column(col3,key='-col3-')], 
                    [sg.Text('')] 
                    ])
                ],

                [sg.Button('Launch', button_color=('white', 'springgreen4'), size=(30,2), font='Helvetica 14'), sg.Button('Cancel',size=(30,2), font='Helvetica 14')] 
                ]
        self.window=sg.Window('PenTasker   -   v. 0.1', layout, element_justification='c', font=("Helvetica", 12),icon='Images/PenTasker-icon.png')

