#!/usr/bin/env python3
# Slow UDP DNS responder on 127.0.0.1:5353. Waits 2s before answering so the
# hijacker's forged reply wins the race. Used only to keep the query socket
# alive; the client should accept the hijacker's response first.
import socket, struct, time

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 5353))
print("slow dns server on 127.0.0.1:5353", flush=True)
while True:
    data, addr = s.recvfrom(4096)
    txid = data[:2]
    # build a trivial A response for whatever was asked, 2s late
    time.sleep(2)
    resp = txid + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
    resp += data[12:]  # echo question
    resp += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x02\x00\x00\x04\x05\x06\x07\x08"
    try:
        s.sendto(resp, addr)
    except OSError:
        pass
