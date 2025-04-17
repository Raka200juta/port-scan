import socket
import threading
import requests
import dns.resolver
from ftplib import FTP
from datetime import datetime
from tqdm import tqdm

def scan_http(ip, port):
    try:
        url = f"http://{ip}:{port}"
        response = requests.get(url, timeout=2)
        print(f"    [+] HTTP Server: {response.headers.get('Server', 'Unknown')}")
        print(f"    [+] Status Code: {response.status_code}")
    except Exception:
        print(f"    [-] HTTP scan failed on port {port}")

def scan_dns(ip):
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ip]
        resolver.timeout = 2
        answer = resolver.resolve('google.com', 'A')
        print(f"    [+] DNS Server responding")
        print(f"    [+] Records found: {len(answer)}")
    except Exception:
        print(f"    [-] DNS scan failed")

def scan_ftp(ip, port):
    try:
        ftp = FTP()
        ftp.connect(ip, port, timeout=2)
        banner = ftp.getwelcome()
        print(f"    [+] FTP Server: {banner}")
        ftp.quit()
    except Exception:
        print(f"    [-] FTP scan failed on port {port}")

def scan_ssh(ip, port):
    try:
        import paramiko
        ssh = paramiko.Transport((ip, port))
        ssh.start_client()
        banner = ssh.get_banner()
        if banner:
            print(f"    [+] SSH Version: {banner.decode()}")
        ssh.close()
    except Exception:
        print(f"    [-] SSH scan failed on port {port}")

def banner_grab(ip, port):
    try:
        sock = socket.socket()
        sock.settimeout(1)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode(errors='ignore').strip()
        if banner:
            print(f"    [*] Banner: {banner}")
        sock.close()
    except Exception:
        print(f"    [-] Cannot grab banner from port {port}")

def scan_port(target, port, results):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target, port))
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except Exception:
                service = "Unknown"
            results.append(f"[+] Port {port} ({service}) terbuka")
            if port in [80, 443]:
                scan_http(target, port)
            elif port == 53:
                scan_dns(target)
            elif port == 21:
                scan_ftp(target, port)
            elif port == 22:
                scan_ssh(target, port)
            else:
                banner_grab(target, port)
        sock.close()
    except Exception:
        pass

def save_results(target, results, filename):
    with open(filename, 'w') as f:
        f.write(f"Scan results for {target}\n")
        f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for result in results:
            f.write(f"{result}\n")

def validate_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def validate_port(port):
    return 1 <= port <= 65535

def main():
    print("=== Enhanced Port Scanner ===\n")
    print("Scanning Modes:")
    print("1. Quick scan (common ports)")
    print("2. Full scan (all ports)")
    print("3. Custom range\n")

    mode = input("Select mode (1-3): ")
    target = input("Enter target IP: ")

    if not validate_ip(target):
        print("Invalid IP address.")
        return

    if mode == "1":
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 8080]
    elif mode == "2":
        ports = range(1, 65536)
    else:
        start_port = int(input("Start port: "))
        end_port = int(input("End port: "))
        if not (validate_port(start_port) and validate_port(end_port)):
            print("Invalid port range.")
            return
        ports = range(start_port, end_port + 1)

    print(f"\nStarting scan on {target} ...")
    print(f"Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    results = []
    threads = []
    max_threads = 100

    with tqdm(total=len(ports), desc="Scanning") as pbar:
        for port in ports:
            while threading.active_count() > max_threads:
                pass  # Wait if too many threads
            t = threading.Thread(target=scan_port, args=(target, port, results))
            threads.append(t)
            t.start()
            pbar.update(1)

        for t in threads:
            t.join()

    print("\nScan Results:")
    for result in sorted(results):
        print(result)

    save = input("\nSave results to file? (y/n): ").lower()
    if save == 'y':
        filename = input("Filename: ")
        save_results(target, results, filename)
        print(f"Results saved to {filename}")

    print(f"\nScan finished at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()