import os
from scapy.all import *
import time
import subprocess
import signal
import functools
import csv

from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
from libnmap.objects.os import NmapOSClass

from os import listdir
from os.path import isfile, join

services = {}

ignore = [80, 443]

with open('services.csv') as csv_file:
    csv_reader = csv.reader(csv_file, delimiter=',')
    line_count = 0
    for row in csv_reader:
        if line_count == 0:
            # port, service, desc
            print(f'Column names are {", ".join(row)}')
            line_count += 1
        else:
            port, service, desc = row
            port = int(port)
            if port not in ignore:
                services[str(port)] = [service, desc]
    print(f'Processed {line_count} lines.')

def run_bash(bashCommand):
    with open("stdout.txt","wb") as out, open("stderr.txt","wb") as err:
        process = subprocess.Popen(bashCommand.split(), stdout=out,stderr=err)
        process.wait()
        output, error = process.communicate()
    print("Output:\n", output)
    print("Error:\n", error)
    return output

def run_bash_timeout(bashCommand, timeout=False):
    process = subprocess.Popen(
        bashCommand.split(), stdout=subprocess.PIPE, preexec_fn=os.setsid)
    if timeout:
        try:
            time.sleep(timeout)
        except KeyboardInterrupt:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    return True

@functools.lru_cache(maxsize=256, typed=True)
def fingerprint_hostname(hostname):
    if hostname[:3]=="192":
        nmproc = NmapProcess(targets=hostname, options="-O")
        rc=nmproc.run()
        parsed = NmapParser.parse(nmproc.stdout)
        host = parsed.hosts[0]
        os_match = []
        if host.os_fingerprinted:
            fingerprint = host.os.osmatches
            for osm in host.os.osmatches:
                #print("Found Match:{0} ({1}%)".format(osm.name, osm.accuracy))
                fingerprint = str(osm.osclasses).replace("\n","").replace("   |__", "").replace("\r","").replace("[","").replace("]","")
                #for osc in osm.osclasses:
                #    os_match.append(str(osc.description))
                    #print("\tOS Class: {0}".format(osc.description))
        else:
            fingerprint = None
        services = []
        for serv in host.services:
            services.append(str(serv.port) + "/" + str(serv.service))
            #print("Open ports:", services)

        return [fingerprint, services]
    else:
        return ["external", "unknown"]

def check_traffic(packet, port, type_name, desc=""):
    port = int(port)
    if packet[TCP].dport == port or packet[TCP].sport == port:
        print("\n\n\n[*] "+type_name, desc)
        print('[*] TX:', packet[IP].src, fingerprint_hostname(packet[IP].src))
        print('[*] RX:', packet[IP].dst, fingerprint_hostname(packet[IP].dst))
        print_payload(packet)
        return True
    else:
        return False

def print_payload(packet, cutoff="600"):
    payload = str(packet[TCP].payload)
    if "Content-Type: application/javascript" in payload:
        print('[*]', "JavaScript File:", payload[:100])
    elif "Content-Type: text/html" in payload:
        print('[*]', "HTML File:", payload[:100])
    else:
        if len(payload) < cutoff:
            print('[*]', payload)
        else:
            print('[*]', payload[:cutoff])

def extra_info_extract(pcap):
    a = rdpcap(pcap)
    sessions = a.sessions()
    for session in sessions:
        for packet in sessions[session]:
            try:
                if packet[TCP].payload:
                    data_packet = str(packet[TCP].payload)
                    if 'PUT' in data_packet or 'POST' in data_packet:
                        print('\n\n\n[*] PUT/POST Request')
                        print('[*] TX:', packet[IP].src, fingerprint_hostname(packet[IP].src))
                        print('[*] RX:', packet[IP].dst, fingerprint_hostname(packet[IP].dst))
                        print_payload(packet, 1000)
                    elif 'admin' in data_packet.lower() or 'login' in data_packet.lower() or 'passw' in data_packet.lower():
                        print('\n\n\n[*] Possible Credentials')
                        print('[*] TX:', packet[IP].src, fingerprint_hostname(packet[IP].src))
                        print('[*] RX:', packet[IP].dst, fingerprint_hostname(packet[IP].dst))
                        print_payload(packet, 1000)

                    check_traffic(packet, 102, "Siemens OT")
                    check_traffic(packet, 502, "Modbus OT")
                    check_traffic(packet, 1883, "MQTT")
                    check_traffic(packet, 44818, "CIP", "Common Industrial Protocol")

                    for port in services:
                        if check_traffic(packet, port, services[port][0], services[port][1]):
                            break
                
            except Exception as e:
                print('[ERROR *]', e)

OUTPUT_DIR = "./output/"

files_list = [f for f in listdir(OUTPUT_DIR) if isfile(join(OUTPUT_DIR, f))]

try:
    while True:

        old_files_list = files_list.copy()

        pcap_name = str(time.time())+".pcap"

        print("pcap_name:", pcap_name)

        print("Starting capture...")

        run_bash("touch "+pcap_name)
        run_bash("chmod 777 "+pcap_name)
        run_bash("chmod 777 -R ./output")
        run_bash_timeout("sudo tshark -i ens33 -w " + pcap_name, 10)

        print("Ended capture...")

        print("Exporting objects...")
        run_bash("sudo tshark -r " + pcap_name + " --export-objects http,./output/")
        run_bash("sudo tshark -r " + pcap_name + " --export-objects smb,./output/")
        run_bash("sudo tshark -r " + pcap_name + " --export-objects tftp,./output/")

        files_list = [f for f in listdir(OUTPUT_DIR) if isfile(join(OUTPUT_DIR, f))]
        if len(old_files_list) != len(files_list):
            print("[**] New objects!")

        print("Done exporting objects...")

        extra_info_extract(pcap_name)

        print("Starting New Loop")

except Exception as e:
    print('[ERROR *]', e)
