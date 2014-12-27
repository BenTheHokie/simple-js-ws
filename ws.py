#!/usr/bin/env python
import socket
import sha
from base64 import b64encode
import re
from wsparse import wsparse


def getSecKey(key):
    GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11' # This is a number specified by the standard (do not change)
    return b64encode(sha.new(key+GUID).digest()) # Concatenate the key and GUID to get the secret hash

def httpparse(headers):
    return dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", headers)) 

def datahandler(data):
    try: # If there is http data, parse that
	data2 = httpparse(data)
	if data2['Upgrade'].lower()=='websocket':
	    return wsug(data2) # if the client is looking for websocket verification, give it to them
    except KeyError:
	print wsparse(data)['text']

def wsug(data):
    response = [
		 'HTTP/1.1 101 Switching Protocols',
		 'Connection: Upgrade',
		 'Upgrade: WebSocket',
		 'Sec-WebSocket-Accept: %s' % getSecKey(data['Sec-WebSocket-Key'])
	       ]
    print "sent wsug response"
    ret='\r\n'.join(response)+'\r\n'*2
    return ret

s=socket.socket()
s.bind(('',8080))
s.listen(1)
print "socket ready..."
conn, addr = s.accept()
print 'Connected by', addr
try:
    while 1:
        data = conn.recv(1024)
	rdata = datahandler(data)
	if rdata:
	    conn.sendall(rdata)
	    print "Sent\n",rdata
except KeyboardInterrupt:
    raise
finally:
    conn.close()
    s.shutdown(socket.SHUT_RDWR)
    s.close()
    print "closed."

