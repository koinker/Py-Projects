import socket
import threading

IP = input("Enter host to scan: ")
ports = [20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 119, 123,
         135, 139, 143, 156, 161, 162, 179, 194, 389, 443, 8080]

def scan(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect((IP, port))
        print(f'Port {port} is open')
    except socket.error:
        print(f'Port {port} is closed')
    finally:
        s.close()

threads = []
for port in ports:
    t = threading.Thread(target=scan, args=(port,), daemon=True)
    threads.append(t)

for thread in threads:
    thread.start()


for thread in threads:
    thread.join()

print("Scan completed.")

