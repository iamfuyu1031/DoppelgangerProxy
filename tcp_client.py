#!/usr/bin/env python 

""" 
A simple echo client 
""" 
import time
import socket 

host = 'localhost' 
port = 10000 
size = 1024 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port)) 
while 1:
	s.send('hello world') 
	time.sleep(0.5)
	data = s.recv(size) 
	print 'Received:', data
