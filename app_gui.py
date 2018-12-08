import time
import subprocess
import signal
import functools
import csv
import os
from os import listdir
from os.path import isfile, join

from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
from libnmap.objects.os import NmapOSClass

from scapy.all import *

import eel

eel.init('web')

class capture_thread():

    def __init__(self, iface="ens33"):
        # Initiate properties
        self.OUTPUT_DIR = "./output/"
        self.iface = iface
        self.stopped = False
        self.old_files_list = []
        self.files_list = [f for f in listdir(self.OUTPUT_DIR) if isfile(join(self.OUTPUT_DIR, f))]

        self.services = {}
        self.ignored_ports = [80, 443]
        with open('services.csv') as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            line_count = 0
            for row in csv_reader:
                port, service, desc = row
                port = int(port)
                if port not in self.ignored_ports:
                    self.services[str(port)] = [service, desc]
            print(f'Processed {line_count} lines.')

    def start(self):
        # start the thread
        self.start_time = time.time()
        Thread(target=self.update, args=()).start()
        return self

    def update(self):
        # keep looping infinitely until the thread is stopped
        global strip, yellow, green
        while True:
            if self.stopped:
                return
            else:
                self.run_event_loop()

    def run_event_loop(self):
        self.old_files_list = self.files_list.copy()

        pcap_name = str(time.time())+".pcap"
        print("pcap_name:", pcap_name)
        print("Starting capture...")

        self.run_bash("touch "+pcap_name)
        self.run_bash("chmod 777 "+pcap_name)
        self.run_bash("chmod 777 -R ./output")
        self.run_bash_timeout("sudo tshark -i "+self.iface+" -w " + pcap_name, 10)

        print("Ended capture...")

        print("Exporting objects...")
        self.run_bash("sudo tshark -r " + pcap_name + " --export-objects http,./output/")
        self.run_bash("sudo tshark -r " + pcap_name + " --export-objects smb,./output/")
        self.run_bash("sudo tshark -r " + pcap_name + " --export-objects tftp,./output/")

        self.files_list = [f for f in listdir(self.OUTPUT_DIR) if isfile(join(self.OUTPUT_DIR, f))]
        if len(self.old_files_list) != len(self.files_list):
            print("[**] New objects!")

        print("Done exporting objects...")

        self.extra_info_extract(pcap_name)


    def run_bash(self, bash_command):
        with open("stdout.txt","wb") as out, open("stderr.txt","wb") as err:
            process = subprocess.Popen(bash_command.split(), stdout=out,stderr=err)
            process.wait()
            output, error = process.communicate()
        return output

    def run_bash_timeout(self, bash_command, timeout=False):
        process = subprocess.Popen(bash_command.split(), stdout=subprocess.PIPE, preexec_fn=os.setsid)
        if timeout:
            try:
                time.sleep(timeout)
            except KeyboardInterrupt:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        return True

    @functools.lru_cache(maxsize=256, typed=True)
    def fingerprint_hostname(self, hostname):
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

    def check_traffic(self, packet, port, type_name, desc=""):
        port = int(port)
        if packet[TCP].dport == port or packet[TCP].sport == port:
            print("\n\n\n[*] "+type_name, desc)
            print('[*] TX:', packet[IP].src, self.fingerprint_hostname(packet[IP].src))
            print('[*] RX:', packet[IP].dst, self.fingerprint_hostname(packet[IP].dst))
            output = self.print_payload(packet)

            tx = str(packet[IP].dst) +"<br><small>" + str(self.fingerprint_hostname(packet[IP].dst)) + "</small>"
            rx = str(packet[IP].src) +"<br><small>" + str(self.fingerprint_hostname(packet[IP].src)) + "</small>"
            eel.add_to_table(type_name+" "+desc, tx, rx , output)

            return True
        else:
            return False

    def print_payload(self, packet, cutoff=600):
        payload = str(packet[TCP].payload)[1:-1]
        try:
            if "Content-Type: application/javascript" in payload:
                to_print = "JavaScript File: "+payload[:100]
            elif "Content-Type: text/html" in payload:
                to_print = "HTML File: "+payload[:100]
            else:
                if len(payload) < cutoff:
                    to_print = payload
                else:
                    to_print = payload[:cutoff]
        except Exception as e:
            to_print = str(e)
        return to_print

    def stop(self):
        self.stopped = True

    def extra_info_extract(self, pcap):
        a = rdpcap(pcap)
        sessions = a.sessions()
        for session in sessions:
            for packet in sessions[session]:
                try:
                    if packet[TCP].payload:
                        data_packet = str(packet[TCP].payload)
                        if 'PUT' in data_packet or 'POST' in data_packet:
                            print('\n\n\n[*] PUT/POST Request')
                            print('[*] TX:', packet[IP].src, self.fingerprint_hostname(packet[IP].src))
                            print('[*] RX:', packet[IP].dst, self.fingerprint_hostname(packet[IP].dst))
                            output = self.print_payload(packet, 1000)
                            tx = str(packet[IP].dst) +"<br><small>" + str(self.fingerprint_hostname(packet[IP].dst)) + "</small>"
                            rx = str(packet[IP].src) +"<br><small>" + str(self.fingerprint_hostname(packet[IP].src)) + "</small>"
                            eel.add_to_table("PUT/POST Request", tx, rx , output)

                        elif 'admin' in data_packet.lower() or 'login' in data_packet.lower() or 'passw' in data_packet.lower():
                            print('\n\n\n[*] Possible Credentials')
                            print('[*] TX:', packet[IP].src, self.fingerprint_hostname(packet[IP].src))
                            print('[*] RX:', packet[IP].dst, self.fingerprint_hostname(packet[IP].dst))
                            output = self.print_payload(packet, 1000)
                            tx = str(packet[IP].dst) +"<br><small>" + str(self.fingerprint_hostname(packet[IP].dst)) + "</small>"
                            rx = str(packet[IP].src) +"<br><small>" + str(self.fingerprint_hostname(packet[IP].src)) + "</small>"
                            eel.add_to_table("Possible Credentials", tx, rx , output)

                        self.check_traffic(packet, 102, "Siemens OT")
                        self.check_traffic(packet, 502, "Modbus OT")
                        self.check_traffic(packet, 1883, "MQTT")
                        self.check_traffic(packet, 44818, "CIP", "Common Industrial Protocol")

                        for port in self.services:
                            if self.check_traffic(packet, port, self.services[port][0], self.services[port][1]):
                                break
                    
                except Exception as e:
                    print('[ERROR *]', e)

capture = capture_thread("ens33")

capture.start()

print("SUPPPPP")

eel.start('index.html') # blocking