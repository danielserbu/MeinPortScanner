import sys
import socket
import argparse
import re

parser = argparse.ArgumentParser(description="Mein Port Scanner")
parser.add_argument("-a", "--address(es)", help="IP addresses to scan")
parser.add_argument("-p", "--ports", help="Ports to look for. Default first 1024")
parser.add_argument("-iL", "--inputlist", help="File containing addresses to scan")
parser.add_argument("-oF", "--outputfile", help="Path to output file")
parser.add_argument("-sS", "--synscan", action='store_true', help="Whether to do a SYN scan")
parser.add_argument("-sN", "--tcpscan", action='store_true', help="Whether to do a TCP scan")
parser.add_argument("-O", "--osprobe", action='store_true', help="Whether to check target operating system")

args = parser.parse_args()
addresses = [x.strip() for x in args.address.split(',')]  # split line by comma
if not addresses:
    print("You have to specify at least one address or a range")
    print("Exiting..")
    exit()
ports = args.ports
inputlist = args.inputlist
outputfile = args.outputfile
synscan = args.synscan
tcpscan = args.tcpscan
osprobe = args.osprobe

MIN_IP_BIT_SEGMENT = 0
MAX_IP_BIT_SEGMENT = 255
MIN_PORT = 0
MAX_PORT = 65535
MOST_KNOWN_PORTS = 1024

ALL_PORTS = range(MIN_PORT, MAX_PORT)
DEFAULT_PORTS_TO_SCAN = range(MIN_PORT, MOST_KNOWN_PORTS)

addresses_to_scan = []
ports_to_scan = DEFAULT_PORTS_TO_SCAN

open_ports_for_addresses = {}  # For each address open ports dictionary

if "*" in addresses:
    for address in addresses:
        for i in range(MIN_IP_BIT_SEGMENT, MAX_IP_BIT_SEGMENT):
            address.replace("*", i)
            # Add address to scan list
            addresses_to_scan.append(address)

if "-" in addresses:
    for address in addresses:
        match = re.search('\d+-\d+', address)
        first_address = int(match.group().split('-')[0])
        last_address = int(match.group().split('-')[1])

        # Validate received addresses.
        if (first_address or last_address) > MAX_IP_BIT_SEGMENT:
            print("IP segment can't be higher than " + str(MAX_IP_BIT_SEGMENT))
            print("Exiting..")
            exit()
        if first_address > last_address:
            print("First address can't be higher than last address")
            print("Exiting..")
            exit()

        position_in_match = match.span()[0]
        address = address[0:position_in_match]
        print(address)
        range_from_first_address_to_last = range(first_address, last_address)
        for i in range_from_first_address_to_last:
            address = address + i
            addresses_to_scan.append(address)

if ports:
    # ToDo: Add switch case instead :D
    if "*" in ports:
        ports_to_scan = ALL_PORTS
    if "," in ports:
        ports_to_scan = [x.strip() for x in args.ports.split(',')]
    if "-" in ports:
        match = re.search('\d+-\d+', ports)
        first_port = int(match.group().split('-')[0])
        last_port = int(match.group().split('-')[1])

        # Validate received ports.
        # ToDo: This kind of validation should be done for "," case too
        if (first_port or last_port) > MAX_PORT:
            print("Port cannot be higher than " + str(MAX_PORT))
            print("Exiting..")
            exit()
        if first_port > last_port:
            print("First port can't be higher than last port")
            print("Exiting..")
            exit()

        range_from_first_port_to_last = range(first_port, last_port)
        for i in range_from_first_port_to_last:
            ports_to_scan.append(i)

def test_port(ip, port, result=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        r = sock.connect_ex((ip, port))
        if r == 0:
            result = r
        sock.close()
    except Exception as e:
        print("Exception was " + e)
        pass
    return result


for port in ALL_PORTS:
    sys.stdout.flush()
    response = test_port(address, port)
    if response == 0:
        open_ports.append(port)

if open_ports:
    print("Open Ports are: ")
    print(sorted(open_ports))
else:
    print("No open ports found")
