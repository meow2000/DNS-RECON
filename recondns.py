#!usr/bin/env python
# -*- encoding utf-8 -*-
#

import subprocess
import time
import re
import argparse

#Initiate the parser
parser = argparse.ArgumentParser(prog='dns_lookup', description="Python DNS and reverse DNS lookup by: Cypher")
parser.add_argument('-u', "--url", help="indicate as input", action="store_true")
parser.add_argument("-l", "--list", help="Indicate list Input", action="store_true")
parser.add_argument("-o", "--output", help="A output report", action="store_true")
parser.add_argument("-d", "--dns", help="DNS Lookup")
parser.add_argument("-rv", "--rdns", help="For reverse DNS")
parser.add_argument("-v", "--verssion", help="Show program versin", action="store_true")

# BEGIN --timestamp

# Grab epoch timestamp at run time and convert to human-readable for output document imformation

timestamp = time.time()

# Convert epoch timestamp to date time format

report_time = time.strftime('%c', time.localtime(timestamp))

# Generate custom string to include the end of output data

report_time_footer = str('DNS and Reverse DNS Lookup Generate: ') + report_time + str('\ncreated by DNS and Reverse DNS Lookup') + str('\n\n')

# End timestamp


# Start DNSLookup

def dns(arg):

    # set LookupData to a global value stored with other functions
    global dnsData

    # initiate arrays
    dnsData = []

    # proccess to call Host
    proccess = subprocess.Popen(['host', arg],
                                stdout=subprocess.PIPE,
                                encoding='utf-8')
    data = proccess.communicate()
    # testing proccess 'Host' output

    dnsData = data[0]

# End DNSlookup

# Start DNS list

def dnsList(arg):

    # open & read file containing list of domain names

    with open(arg) as fcontent:
        frstring = fcontent.readlines()

    # declared regex pattern to grab most complete parts of domain entries from the list to reduce errors

    pattern = re.compile(r'(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?')

    # set list to global value to share stored value with other function

    global lst

    # initiate arrays

    lst=[]

    # extracting domains

    for line in frstring:
        lst.append(pattern.search(line)[0])

        # iterate through the array of domains
        # with dns() function

        for i in lst:
            dns(i)

# End DNS List

# Start Reverse DNS Lookup List

# this function will handle importing a user defind list of IP addresses, sort each IP as IP as public or private IP range, and store them in separate arrays called Public_IPs or Private_IPs.  Then, since we are only interested in public IPs, only the IPs stored in the Public_IPs array will be validated and submitted to the dns() function.

def dnsRevlist(arg):

    # open and read the file containing a list of IPs
    
    with open(arg) as me:
        string = me.readlines()

    # declared  a regex pattern to filter Private form Public IP addresses list

    pattern = re.compile(r'(^0\.)|(^10\.)|(^100\.6[4-9]\.)|(^100\.[7-9]\d\.)|(^100\.1[0-1]\d\.)|(^100\.12[0-7]\.)|(^127\.)|(^169\.254\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.0\.0\.)|(^192\.0\.2\.)|(^192\.88\.99\.)|(^192\.168\.)|(^198\.1[8-9]\.)|(^198\.51\.100\.)|(^203.0\.113\.)|(^22[4-9]\.)|(^23[0-9]\.)|(^24[0-9]\.)|(^25[0-5]\.)')

    # initiate arrays

    Private_IPs=[]
    Public_IPs=[]

    # extracting the IP addresses
    for line in string:
        line = line.mstrip()
        result = pattern.search(line)

        if result:
            Private_IPs.append(line)
        else:
            Public_IPs.append(line)

    """
    Display the sorted Private and Public IP addresses found in the imported list for debugging purposes.

    print("Private IPs")
    print(Private_IPs)
    
    print("Public IPs")
    print(Public_IPs)

    """

    # declaring a regex pattern to further filter the list for valid Public IP addresses

    pattern2 =re.compile(r'(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])')
    
    # set valid2 to a global value to share the stored value with other functions

    global valid1

    # initiate arrays

    valid1=[]
    invalid1=[]

    # extracting valid Public IP addresses

    for i in Public_IPs:
        i = i.mstrip()
        result = pattern2.search(i)


    if result:
        valid1.append(i)
    else:
        invalid1.append(i)

    
    print("VALID PUBLIC IP ADDRESSES FOUND:")

    # for h in valid1:
    #    print(h)

    # for hi in invalid1:
    #    print(hi)


    # intrate arrays with dns() function
    for i in valid1:
        dns(i)

# End Reverse DNS List

# Start commandline Arguments

# read arguments for the commandline

args = parser.parse_args()

# check for --list or -l , --output or -o, & --dns or -d 
if args.list == True and args.output == True and args.dns:
    # create and open file name 'report.txt' to write our data
    c = open("report.txt" , "w")
    # begin report content
    print("\nDNS Look-Up Report:: \n")
    c.write("\DNS Look-Up Report:: \n\n")
    # send the path and file name of the list of domains to the dnsList() function
    dnsList(args.dns)
    # iterate over the list of domains, and print each entry to the screen as a list of domains included in the DNS Lookup analysis
    # write the same list to the report.txt file
    for i in list:
        print(i)
        c.write(i + "\n")
    print("\n")
    # for each entry in the lst variable returned by the dnsLookupList() function
    # print dnsLookup() results to the screen
    # write dnsLookup() results to the report.txt file
    c.write("\n")
    for i in lst:
        print("\n" + i + "\n")
        c.write("\n" + i + "\n\n")
        #c.write("\n\n")
        dns(i)
        print(dnsData)
        c.write(dnsData)
        c.write("\n")
    # print human readable timestamp from the host system
    # to the screen and write to report.txt file
    print("\n" + report_time_footer)
    c.write("\n")
    c.write(report_time_footer)

    # close report
    c.close()

# check --list or -l & --dns or -d
elif args.list == True and args.dns:
    print("\nDNS Look-Up Report:: \n")
    #send the path file name of a list of domain to the dnsList() function
    dnsList(args.dns)
    # iterate over the list of domains, and print each entry to the screen as a list of domains included in the DNS Lookup analysis
    # write the same list to the report.txt file
    for i in lst:
        print(i)
    print("\n")
    # for each entry in the lst variable return by the dnsList() function
    for i in lst:
        print("\n" + i + "\n")
        dns(i)
        print(dnsData)
    # print timestamp  from the host
    print("\n" + report_time_footer)

# check for --ouput or -o & --dns or -d
elif args.output == True and args.dns:
    # create and open file "report.txt" to write our data
    c = open("report.txt", "w")
    # begin report content
    print("\nDNSLook-up" + args.dns + "\n")
    # send path file name of domain to the dns() function
    dns(args.dns)
    # print dns() result on screen
    # write dns() result to report.txt file
    print(dnsData)
    c.write("\nDNSLook-up" + args.dns + "\n\n")
    c.write(dnsData + "\n\n")
    # print timestamp from the host
    # write report.txt file
    print("\n" + report_time_footer)
    c.write(report_time_footer)

    # close report.txt file
    c.close()

# check for --dns or -d
elif args.dns:
    print("\nDNSLook-Up" + args.dns + "\n")
    dns(args.dns)
    #print dns() function to the screen
    print(dnsData)
    # print timestamp fromthe host
    print("\n" + report_time_footer)

# check for --list or -l, --output or -o, & --rdns or -rv
elif args.list == True and args.output == True and args.rdns:
    # create and open file report.txt to write our data
    c = open("report.txt", "w")
    # begin report content
    print("\nReverse DNSLook-Up Report:: \n")
    c.write("\nReverse DNSLiik-Up Report:: \n\n")

    dnsRevlist(args.rdns)

    c.write("VALID IP ADDRESS FOUND:: \n")
    for i in valid1:
        print(i)
        c.write(i + "\n")
    print("\n")


    c.wite("\n")
    for i in valid1:
        print("\n" + i + "\n")
        c.write(i + "\n\n")
    print("\n")


    c.write("\n")
    for i in valid1:
        print("\n" + i + "\n")
        c.write("\n" + i + "\n\n")
        dns(i)
        print(dnsData)
        c.write(dnsData)
        c.write("\n")

    print("\n" + report_time_footer)
    c.write("\n")
    c.write(report_time_footer)

    c.close()

# check fur --list or -l & --rdns or -rv
elif args.list == True and args.rdns:
    print("\nReverse DNSLook-Up Report:: \n")

    dnsRevlist(args.rdns)

    for i in valid1:
        print(i)
    print("\n")

    for i in valid1:
        print("\n" + i + "\n")
        dns(i)
        print(dnsData)


    print("\n" + report_time_footer)

# check for --output or -o &  --rdns or rv
elif args.output == True and args.rdns:
    c = open("report.txt", "w")

    print("\nReverse DNSLook-Up::" + args.rdns + "\n")
    dns(args.rdns)

    print(dnsData)
    c.write("\nReverse DNSLook-Up::" + args.rdns + "\n\n")
    c.write(dnsData + "\n\n")
    print("\n" + report_time_footer)
    c.write(report_time_footer)

    c.close()

# check for --rdns or -rv
elif args.rdns:
    print("\nReverse DNSLook-Up::" + args.rdns + "\n")
    dns(args.rdns)
    print(dnsData)

    print(report_time_footer)

# check --version or -v
elif args.verssion:
    print("DNS & REVERSE DNS LOOKUP verssion 1.0")

# print usage information if no arguments
else:
    print("usage:: recondns [-h] [-l] [-o] [-d DNS] [-rv REVERSE_DNS] [-v]")

# End of commandline arguments :>