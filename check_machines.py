#!/usr/bin/python
#
# Author: Tony Saxon
# Date: 4/4/11
#
# This script will prompt for an IP, hostname, or subnet and credentials. It will
# then scan whatever you enter with nmap for items listening on port 22. It will
# try to log into the machines that it finds and gather the serial number, hostname,
# and listing of user home directories that exist and output all this information
# to a csv file for easy reading.
#
# Requirements:
#	- sudo for OS detection
#	- paramiko module (http://www.lag.net/paramiko/)
#	- nmap (/usr/bin/nmap)

import paramiko
from lxml import etree
import subprocess
import getpass

def getSubnet():
	global subnet
	subnet = raw_input("Enter the subnet or IP that you want to scan: ")

def getCreds():
	global username
	username = raw_input("Username: ")
	global password
	password = getpass.getpass(prompt="Password: ")

def scan():
	devnull = open('scan.xml', 'w')
	subprocess.call(["sudo", "nmap", "-p22", "-O", "-oX", "-", subnet], stdout=devnull)
	devnull.close()
	scanresults = etree.parse('scan.xml')
	for hostobject in scanresults.iter(tag='host'):
		osguess = []
	        for subelement in hostobject.iter():
	                global ipAddress
	                global portState
	                if subelement.tag == "address" and subelement.get('addrtype') == "ipv4":
	                         ipAddress = subelement.get('addr')
	                if subelement.tag == "state":
	                        portState = subelement.get('state')
			if subelement.tag == "osmatch":
				osguess.append("(%s%%) %s" % (subelement.get('accuracy'), subelement.get('name')))
        	if portState == 'open':
			checkMachine(ipAddress, osguess)

def checkMachine(host, osguess=[]):
	devnull = open('/dev/null', 'w')
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	try:
		ssh.connect(host,username=username,password=password)
        	stdin, stdout, stderr = ssh.exec_command("dmidecode | grep -m 1 -i serial\ number | awk '{print $3}'")
        	serNum = stdout.readline().rstrip('\n')
		stdin, stdout, stderr = ssh.exec_command("hostname")
		hostName = stdout.readline().rstrip('\n')
		stdin, stdout, stderr = ssh.exec_command("ls /home")
		homeDirs = stdout.read().splitlines()
		stdin, stdout, stderr = ssh.exec_command("if [ -e /etc/lsb-release ]; then cat /etc/lsb-release | grep DESCRIPTION | awk '{split($0,a,\"=\"); print a[2]}'; elif [ -e /etc/redhat-release ]; then cat /etc/redhat-release; else echo OS not detected!; fi")
		opsys = stdout.readline().rstrip('\n')
        	ssh.close
		outfile.write("%s,%s,%s,\"%s\",%s\n" % (host,hostName,serNum,', '.join(homeDirs),opsys))
	except paramiko.AuthenticationException:
		# Get the hostname
		hostName = subprocess.Popen(["host", host], stdout=subprocess.PIPE).communicate()[0]
		outfile.write("%s,%s,N/A,N/A,\"%s\",Unable to authenticate to this machine as root\n" % (host,hostName.strip().split("\n")[0],', '.join(osguess)))
	except:
		print "Something else went wrong:"
		print "Host: " + host + "\n"
	devnull.close()

getSubnet()
getCreds()
outfile = open('results.csv','w')
outfile.write("IP Address,Host Name,Serial Number,Existing Home directories,Detected OS,Notes\n")
scan()
outfile.closed
print "The script has finished running.\nThe results are saved in results.csv."
