import argparse, os, re
from subprocess import PIPE, Popen
 
__author__ = 'Caleb Kinney, ASM Research, EAS Team (caleb.kinney@asmr.com)'
 
 
def get_args():
    parser = argparse.ArgumentParser(
        description='Enumerate SSL Ciphers')
    parser.add_argument(
        '-i', '--ip', type=str, help='IP Address', required=True)
    args = parser.parse_args()
    ip = args.ip
    return ip
 
ip = get_args()
ip = ip.replace(',',' ')
 
print("\n")
print("\033[1;31m       ::::::::::     :::      ::::::::  ")
print("       :+:          :+: :+:   :+:    :+:  ")
print("       +:+         +:+   +:+  +:+         ")
print("       +#++:++#   +#++:++#++: +#++:++#++  ")
print("       +#+        +#+     +#+        +#+  ")
print("       #+#        #+#     #+# #+#    #+#  ")
print("       ########## ###     ###  ########   ")
print(" __ _ _  _ ____ ___    ____ ____ ____ _ ___  ___ ")
print(" | \| |\/| |--| |--'   ==== |___ |--< | |--'  |  ")
 
print "\033[1;37m\nScanning IP Address(es): [ %s ]" % ip
 
 
def cmdline(command):
    process = Popen(
        args=command,
        stdout=PIPE,
        shell=True
    )
    return process.communicate()[0]
 
def nmapHostDiscover():
    nmapHostScan = ("nmap -sP %s | grep 'Nmap scan report for' | cut -f 5 -d ' ' | awk -vORS=, '{ print $1 }'") % ip
    global openHosts
    openHosts = cmdline(nmapHostScan)
    openHosts = openHosts[:-1]
    print(("\n\033[1;31m Discovered Hosts for %s: \033[1;37m" + openHosts) % ip)
 
def hostsScan():
    for host in openHosts.split(','):
        print("\n\033[1;31m Scanning: \033[1;37m" + host)
        nmapOpenPorts(host)
 
def nmapOpenPorts(hosts):
    nmapsSPortScan = ("nmap -sTU --top-ports 1000 %s | grep open | awk -vORS=, '{ print $1 }' | sed 's/,$//' | grep -o '[0-9]*' | awk -vORS=, '{ print $1 }'") % (hosts)
    global openPorts
    openPorts= cmdline(nmapsSPortScan)
    openPorts = openPorts[:-1]
    print(("\n\033[1;31m Open ports for %s are: \033[1;37m"+ openPorts) % hosts)
    nmapDeepScan = ("nmap -A -T4 " + hosts + " -oA " + hosts + " -p " + openPorts)
    deepScanResults = cmdline(nmapDeepScan)
    print(deepScanResults)
    print("\n!!! EAS nmap Script Complete for " + hosts + "- output saved as " + hosts + ".gnmap/nmap/xml !!!\n\n")
    os.system(("leafpad %s.nmap") % hosts)
 
    deepScanResults = cmdline(nmapDeepScan)
 
def scriptClose():
    print("Script Completed, Thank You for choosing EAS for your penetration testing needs.")
 
nmapHostDiscover()
hostsScan()
scriptClose()
