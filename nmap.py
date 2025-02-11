import socket
import argparse
import threading
import subprocess
import sys
import signal

open_ports = []
keep_running = True
lock = threading.Lock()


def signal_handler(sig, frame):
    global keep_running
    print("\nStopping the scan...")
    keep_running = False
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


# ping function supports windows + linux
def is_device_active(ip):
    try:
        ping_cmd = ["ping", "-c", "1", "-W", "1", ip] if sys.platform != "win32" else ["ping", "-n", "1", ip]
        result = subprocess.run(ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception:
        return False


# Scan a specific port
def scan_port(ip, port):
    global keep_running
    if not keep_running:
        return
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((ip, port)) == 0:
                with lock:
                    open_ports.append(port)
                    print(f"Port {port} is open on {ip}")
    except Exception:
        pass


# Scan a range of ports using threads
def scan_ports(ip, start_port, end_port):
    if is_device_active(ip):
        print(f"Device detected at {ip}, starting scan...")
    else:
        print(f"No response from {ip}, scanning anyway pinging may be blocked.")

    threads = []

    for port in range(start_port, end_port + 1):
        if not keep_running:
            break
        t = threading.Thread(target=scan_port, args=(ip, port))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    open_ports.sort()


def main():
    parser = argparse.ArgumentParser(description="Custom Nmap-like Port Scanner")
    parser.add_argument("-s", action="store_true", help="Scan well-known ports (0-1023)")
    parser.add_argument("-u", action="store_true", help="Scan registered ports (1024-49151)")
    parser.add_argument("-p", action="store_true", help="Scan dynamic/private ports (49152-65535)")
    parser.add_argument("-a", action="store_true", help="Scan all ports (0-65535)")
    parser.add_argument("-i", type=str, required=True, help="Target IP address (e.g., 192.168.1.10)")
    args = parser.parse_args()

    if args.s:
        start_port, end_port = 0, 1023
    elif args.u:
        start_port, end_port = 1024, 49151
    elif args.p:
        start_port, end_port = 49152, 65535
    elif args.a:
        start_port, end_port = 0, 65535
    else:
        print("Error: No port range selected. Use -s, -u, -p, or -a.")
        sys.exit(1)

    if args.i.count('.') != 3:
        print("ERROR: Please enter a full IP address (e.g., 192.168.1.10).")
        sys.exit(1)

    # Begin scan
    scan_ports(args.i, start_port, end_port)


if __name__ == "__main__":
    main()
