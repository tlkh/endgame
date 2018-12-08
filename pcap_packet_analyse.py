import os
from scapy.all import *
import time
import subprocess
import signal
import functools

from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
from libnmap.objects.os import NmapOSClass

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
    nmproc = NmapProcess(targets=hostname, options="-O")
    rc=nmproc.run()
    parsed = NmapParser.parse(nmproc.stdout)
    host = parsed.hosts[0]
    os_match = []
    if host.os_fingerprinted:
        fingerprint = host.os.osmatches
        for osm in host.os.osmatches:
            #print("Found Match:{0} ({1}%)".format(osm.name, osm.accuracy))
            fingerprint = osm.osclasses
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

def check_traffic(packet, port, type_name):
    if packet[TCP].dport == port or packet[TCP].sport == port:
        print("\n\n\n[*] "+type_name+" Traffic")
        print('[*] TX:', packet[IP].src, fingerprint_hostname(packet[IP].src))
        print('[*] RX:', packet[IP].dst, fingerprint_hostname(packet[IP].dst))
        print('[*]', packet[TCP].payload)

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
                        print('[*]', packet[TCP].payload)
                    if 'admin' in data_packet.lower() or 'login' in data_packet.lower() or 'passw' in data_packet.lower():
                        print('\n\n\n[*] Possible Credentials')
                        print('[*] TX:', packet[IP].src, fingerprint_hostname(packet[IP].src))
                        print('[*] RX:', packet[IP].dst, fingerprint_hostname(packet[IP].dst))
                        print('[*]', packet[TCP].payload)

                if packet[TCP].dport == 1883 or packet[TCP].sport == 1883:
                    print('\n\n\n[*] MQTT Traffic')
                    print('[*] TX:', packet[IP].src, fingerprint_hostname(packet[IP].src))
                    print('[*] RX:', packet[IP].dst, fingerprint_hostname(packet[IP].dst))
                    print('[*]', packet[TCP].payload)

                if packet[TCP].dport == 102 or packet[TCP].sport == 102:
                    print('\n\n\n[*] Siemens OT Traffic')
                    print('[*] TX:', packet[IP].src, fingerprint_hostname(packet[IP].src))
                    print('[*] RX:', packet[IP].dst, fingerprint_hostname(packet[IP].dst))
                    print('[*]', packet[TCP].payload)

                if packet[TCP].dport == 502 or packet[TCP].sport == 502:
                    print('\n\n\n[*] Modbus OT Traffic')
                    print('[*] TX:', packet[IP].src, fingerprint_hostname(packet[IP].src))
                    print('[*] RX:', packet[IP].dst, fingerprint_hostname(packet[IP].dst))
                    print('[*]', packet[TCP].payload)

                if (136 < packet[TCP].dport < 140)  or (136 < packet[TCP].sport < 140) or packet[TCP].dport == 445 or packet[TCP].sport == 445:
                    print('\n\n\n[*] SAMBA Traffic')
                    print('[*] TX:', packet[IP].src, fingerprint_hostname(packet[IP].src))
                    print('[*] RX:', packet[IP].dst, fingerprint_hostname(packet[IP].dst))
                    print('[*]', packet[TCP].payload)
                
            except Exception as e:
                print('[ERROR *]', e)

while True:
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

    print("Done exporting objects...")

    extra_info_extract(pcap_name)

    print("New Loop")
