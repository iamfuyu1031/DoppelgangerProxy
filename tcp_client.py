#!/usr/bin/env python 

""" 
A simple echo client 
""" 
import time
import socket 

host = 'localhost' 
port = 10000 
size = 1024 
while 1:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
	s.connect((host,port)) 
	s.send('hello world') 
	time.sleep(0.5)
	data = s.recv(size) 
	s.close() 
	print 'Received:', data
