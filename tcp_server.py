#!/usr/bin/env python 

""" 
A simple echo server 
""" 

import socket 
import time

host = '' 
port = 50000 
backlog = 5 
size = 1024 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host,port)) 
s.listen(backlog) 
client, address = s.accept() 
while 1:
    data = client.recv(size) 
    if data: 
        print 'received data: ' + data
        client.send(data) 
