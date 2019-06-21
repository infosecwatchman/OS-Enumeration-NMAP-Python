#
#      Python script to enumerate network with nmap 
#      as well as basic OS enumeration of each machine provideded the credentials in the beginning
#
#      Place python script in any folder with the following subfolders created:
#      
#      

import re
import subprocess
import os
import sys
import ast
import time


##########################FUNCTIONS####################################

def windowsCleanup():
 os.system('findstr /v /r /c:"^$" /c:"^\ *$" ".\\iplist.txt" > "iplist-test.txt"')
 os.system('more .\\iplist-test.txt > .\\iplist.txt')
 os.system('del .\\iplist-test.txt')
 f = open('iplist.txt', 'r').readlines()

def removeLastLine():
 lines = open('iplist.txt', 'r').readlines() 
 print(lines)
 del lines[-1] 
 print(lines)
 open('iplist.txt', 'w').writelines(lines)
 
def hasNumbers(inputString):
 return any(char.isdigit() for char in inputString)

def linuxCommandsToScript():
 linuxcommands = open(".\\linuxcommands.txt", "w")
 linuxcommands.write("cd /home/")
 linuxcommands.write('\n')
 linuxcommands.write("hostname=\"$(hostname)\"")
 linuxcommands.write('\n')
 linuxcommands.write("file=\"enum${hostname}.txt\"")
 linuxcommands.write('\n')
 linuxcommands.write("hostname >> $file 2>&1")
 linuxcommands.write('\n')
 linuxcommands.write("ifconfig -a >> $file 2>&1")
 linuxcommands.write('\n')
 linuxcommands.write("cat /etc/passwd >> $file 2>&1")
 linuxcommands.write('\n')
 linuxcommands.write("cat /etc/hosts >> $file 2>&1")
 linuxcommands.write('\n')
 linuxcommands.write("service --status-all >> $file 2>&1")
 linuxcommands.write('\n')
 linuxcommands.write("netstat -plant >> $file 2>&1")
 linuxcommands.write('\n')
 linuxcommands.write("cat /etc/group >> $file 2>&1")
 linuxcommands.write('\n')
 linuxcommands.write("cat /etc/os-release >> $file 2>&1")
 linuxcommands.close

def windowsCommandsToScript():
 pwd = os.popen('cd').read()
 pwd = pwd[2:-1]
 windowscommands = open("windowscommands.bat", "w+")
 windowscommands.write('FOR /F "tokens=*" %%a in (\'hostname\') do SET filevar=%%a')
 windowscommands.write('\n')
 windowscommands.write('set "filename=%filevar%.txt"')
 windowscommands.write('\n')
 windowscommands.write('hostname > %filename%')
 windowscommands.write('\n')
 windowscommands.write('ver >> %filename%')
 windowscommands.write('\n')
 windowscommands.write('ipconfig /all >> %filename%')
 windowscommands.write('\n')
 windowscommands.write('powershell get-localuser >> %filename%')
 windowscommands.write('\n')
 windowscommands.write('powershell get-localgroup >> %filename%')
 windowscommands.write('\n')
 windowscommands.write('more C:\\Windows\\System32\\drivers\\etc\\hosts >> %filename%')
 windowscommands.write('\n')
 windowscommands.write('net start >> %filename%')
 windowscommands.write('\n')
 windowscommands.write('netstat -an >> %filename%')
 windowscommands.write('\n')
 windowscommands.write('xcopy /I /F .\\%filename% \\\\' + (ip_addr) + '\\ADMIN$\..' + (pwd) + '\\Results\\%filename%')
 
def linuxCommands():
 command1 = "pscp -pw " + (linuxpassword) + " .\\linuxcommands.sh " + (linuxuser) + "@" + (hostip) + ":/home"
 os.system(command1)
 command2 = "plink -pw " + (linuxpassword) + " -ssh " + (linuxuser) + "@" + (hostip) +  ' "chmod +x /home/enum.sh"'
 os.system(command2)
 command3 = "plink -pw " + (linuxpassword) + " -ssh " + (linuxuser) + "@" + (hostip) + ' "/home/enum.sh"'
 os.system(command3)
 command4 = "pscp -pw " + (linuxpassword) + " " + (linuxuser) + "@" + (hostip) + ':/home/testenum.txt .\\Results\\.'
 
def windowsCommands():
 command0 = "winrm set winrm/config/client '@{TrustedHosts=\"" + (hostip) + "\"}'"
 #print(command0)
 f= open("C:\\test.ps1","w+")
 f.write(command0)
 p = subprocess.Popen(['powershell.exe', 'C:\\test.ps1'], stdout=sys.stdout)
 command1 = "copy .\\windowscommands.bat \\" + (hostip) + "\c$\\windowscommands.bat"
 os.system(command1)
 command2 = ".\\Sysinternals\\psexec.exe -accepteula -h -u " + (windowsuser) + " -p " + (windowspassword) + " \\\\" + (hostip) + " c:\\windowscommands.bat -i"
 fi= open("C:\\psexec-command.bat","w+")
 fi.write(command2)
 command3 = "psexec -accepteula -h -u " + (windowsuser) + " -p " + (windowspassword) + " C:\\psexec-command.bat"
 os.system(command3)

#######################################################################
#Netinput = input('What is the network ID of the network you want to scan?(ie. 192.168.1.0): ')
#cidrinput = input('What is the CIDR of the network you want to scan?(ie. /24) hit enter if single host: ')
ip_addr = input('What is the IP address of the machine you are scanning from?')
linuxuser = input('What is the Linux user that will be used for enumeration?: ')
linuxpassword = input('What is the Linux password used to authenticate the user above?: ')
windowsuser = input('What is the Windows user that will be used for enumeration? Domain user should look like; domain.com\\user: ')
windowspassword = input('What is the Windows password used to authenticate the user above?: ')
#netpluscidr = (Netinput + cidrinput)
#print ('Scanning:', netpluscidr)
#os.system('powershell wget https://the.earth.li/~sgtatham/putty/latest/w32/putty-0.70-installer.msi -OutFile ./putty_installer.msi')
#os.system('start /wait msiexec /i .\\putty_installer.msi /quiet /qn')
#os.system('powershell wget https://download.sysinternals.com/files/SysinternalsSuite.zip -OutFile ./SysinternalsSuite.zip')
#os.system('powershell Expand-Archive SysinternalsSuite.zip .\\Sysinternals')
os.system('mkdir Results')
os.system('mkdir ips')
#os.system('copy NUL .txt')
#command = "nmap -sP -oG .\\nmaplist.txt " + (netpluscidr)
#os.system(command)
windowsCommandsToScript()
linuxCommandsToScript()
hosts = "127.0.0.1"
fh = open("nmaplist.txt")
iplist = open("iplist.txt", "w+")
windowsmachines = open(".\\windowsmachines.txt")
with open ("nmaplist.txt", "r") as r:
 contents = r.read()
 for line in contents.split('\n'):
  if line.startswith('Host: '):
   line1 = line[6:]
   beginline = line[6:10]
   number = str (line1.find(" ("))
   full = "(line1[:" + number + "])"
   command = "print" + full
   writecommand = "iplist.write" + full
   exec(command)
   exec(writecommand)
   iplist.write("\n")
fh.close()
iplist.close()
windowsCleanup()
with open ("iplist.txt", "r") as file:
 filecontents = file.read()
 lists = []
 for line in open('iplist.txt'):
  lists.append(line.strip())
 for line in lists:
  filename = (line) + ".txt "
  command = "nmap -O -oN " + ".\\ips\\" + (filename) + (line)
  strlen = int (len(filename))
  compareline = line[:4]
  pingcommand = "ping " + (line) + " >> .\\ips\\" + (filename)
  os.system(pingcommand)
  hosts = hosts + "," + line 
command0 = "winrm set winrm/config/client '@{TrustedHosts=\"" + (hosts) + "\"}'"
f = open(".\\authhost.ps1","w+")
f.write(command0)
f.close
time.sleep(10)
p = 'powershell.exe .\\authhost.ps1'
files = os.listdir(".\\ips\\")
for file in files:
 realfile = (".\\ips\\" + file)
 hostip = file[:-4]
 with open (realfile, "r") as fileos:
  filenameforos = (file)
  if 'linux' in open(realfile).read() or 'TTL=64' in open(realfile).read(): # Linux enumeration 
   command1 = "pscp -pw " + (linuxpassword) + " .\\linuxcommands.sh " + (linuxuser) + "@" + (hostip) + ":/home"
   os.system(command1)
   command2 = "plink -pw " + (linuxpassword) + " -ssh " + (linuxuser) + "@" + (hostip) +  ' "chmod +x /home/linuxcommands.sh"'
   os.system(command2)
   command3 = "plink -pw " + (linuxpassword) + " -ssh " + (linuxuser) + "@" + (hostip) +  ' "sed -i -e \'s/\\r$//\' /home/linuxcommands.sh"'
   os.system(command3)
   command4 = "plink -pw " + (linuxpassword) + " -ssh " + (linuxuser) + "@" + (hostip) + ' -m .\\linuxcommands.txt'
   os.system(command4)
   time.sleep(5)
   command5 = "pscp -pw " + (linuxpassword) + " " + (linuxuser) + "@" + (hostip) + ':/home/enum* .\\Results\\.'
   os.system(command5)
  elif 'microsoft' in open(realfile).read() or 'TTL=128' in open(realfile).read() or 'TTL=126' in open(realfile).read(): #Windows enumeration 
   if hostip in open(".\\windowsmachines.txt").read():
    #none shall pass!
    print('')
   else:
    windowsmachines = open(".\\windowsmachines.txt", "a")
    windowsmachines.write(hostip)
    windowsmachines.write('\n')
  else: #cannot determine OS
   print('Cannnot determine OS.')
   
time.sleep(10)
windowsremotecommand = "psexec @windowsmachines.txt -u " + windowsuser + " -p " + windowspassword + " -accepteula -h -s -c -f .\\windowscommands.bat"
os.system(windowsremotecommand)
