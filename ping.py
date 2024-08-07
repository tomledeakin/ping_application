import os
import struct
import socket
import time
import select
from tkinter import *
from threading import Thread

ICMP_ECHO_REQUEST = 8

def checksum(source_string):
    sum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0

    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        sum = sum + this_val
        sum = sum & 0xffffffff
        count = count + 2

    if count_to < len(source_string):
        sum = sum + source_string[len(source_string) - 1]
        sum = sum & 0xffffffff

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def create_packet(packet_id, sequence):
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, 0, packet_id, sequence)
    data = struct.pack('d', time.time())
    my_checksum = checksum(header + data)
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), packet_id, sequence)
    return header + data

def send_ping(sock, addr, packet_id, sequence):
    packet = create_packet(packet_id, sequence)
    sock.sendto(packet, (addr, 1))

def receive_ping(sock, packet_id, sequence, timeout):
    time_left = timeout
    while True:
        start_select = time.time()
        ready = select.select([sock], [], [], time_left)
        select_duration = time.time() - start_select
        if ready[0] == []:
            return None
        time_received = time.time()
        rec_packet, addr = sock.recvfrom(1024)

        # Extracting IP header fields
        ip_header = rec_packet[:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        ttl = iph[5]

        # Extracting ICMP header fields
        icmp_header = rec_packet[20:28]
        icmp_type, code, rec_checksum, rec_packet_id, rec_sequence = struct.unpack('bbHHh', icmp_header)
        if rec_packet_id == packet_id and rec_sequence == sequence:
            time_sent = struct.unpack('d', rec_packet[28:28 + struct.calcsize('d')])[0]
            return time_received - time_sent, addr[0], ttl
        time_left -= select_duration
        if time_left <= 0:
            return None

def time_ping(sock, addr, packet_id, sequence, timeout):
    send_ping(sock, addr, packet_id, sequence)
    result = receive_ping(sock, packet_id, sequence, timeout)
    if result is None:
        return None
    else:
        return result

def ping(host, count=6, timeout=1):
    icmp = socket.getprotobyname("icmp")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    except PermissionError as e:
        raise PermissionError("You need to run this script as root/Administrator.") from e

    my_id = os.getpid() & 0xFFFF
    addr = socket.gethostbyname(host)
    print(f"PING {host} ({addr}): 56 data bytes")
    results = []
    for sequence in range(1, count + 1):
        result = time_ping(sock, addr, my_id, sequence, timeout)
        if result is None:
            result_str = f"Request timeout for icmp_seq {sequence}"
        else:
            delay, ip, ttl = result
            result_str = f"64 bytes from {ip}: icmp_seq={sequence} ttl={ttl} time={delay * 1000:.3f} ms"
        results.append(result_str)
        print(result_str)
        time.sleep(1)

    sock.close()
    return "\n".join(results)

def get_ping():
    host = e.get()
    try:
        result = ping(host)
        res.set(result)
    except Exception as ex:
        res.set(str(ex))

# GUI code
master = Tk()
master.configure(bg='light grey')

res = StringVar()

Label(master, text="Enter URL or IP:", bg="light grey").grid(row=0, sticky=W)
Label(master, text="Result:", bg="light grey").grid(row=1, sticky=W)

Label(master, text="", textvariable=res, bg="light grey").grid(row=1, column=1, sticky=W)

e = Entry(master)
e.grid(row=0, column=1)

def run_ping():
    Thread(target=get_ping).start()

b = Button(master, text="Show", command=run_ping)
b.grid(row=0, column=2, columnspan=2, rowspan=2, padx=5, pady=5)

mainloop()
