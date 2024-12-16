import sys
from scapy.all import sniff, TCP, IP
import logging
import time
import re

# Configure logging
logging.basicConfig(
    filename="sniffer.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

def handle_packet(packet, log):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        log.write(f"TCP Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n")
        logging.info(f"TCP Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
    else:
        logging.warning("Packet without IP or TCP layer received.")

def main(interface, verbose=False):
    try:
        print(f"[*] Starting packet capture on interface '{interface}'...")
        logging.info(f"Started sniffing on interface: {interface}")

        # Create a simplified interface name to use for the log file
        # Remove any special characters from the interface name
        clean_interface_name = re.sub(r'[^A-Za-z0-9]+', '_', interface)

        logfile_name = f"sniffer_{clean_interface_name}_log.txt"
        with open(logfile_name, 'w') as logfile:
            start_time = time.time()
            sniff(iface=interface, prn=lambda pkt: handle_packet(pkt, logfile), store=0, timeout=60)
            elapsed_time = time.time() - start_time
            print(f"[*] Sniffing completed after {elapsed_time:.2f} seconds.")
            logging.info(f"Sniffing completed on {interface}. Duration: {elapsed_time:.2f} seconds.")
    except ValueError as e:
        print(f"[!] Error: {e}")
        logging.error(f"Invalid interface: {interface}")
    except KeyboardInterrupt:
        print("\n[!] Sniffing stopped by user.")
        logging.info("Sniffing stopped by user.")
        sys.exit(0)
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python sniffer.py <interface> [verbose]")
        sys.exit(1)

    interface = sys.argv[1]
    verbose = len(sys.argv) == 3 and sys.argv[2].lower() == "verbose"

    main(interface, verbose)
