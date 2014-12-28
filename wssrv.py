#!/usr/bin/env python
import socket
import sha
from base64 import b64encode
import re
from wsparse import wsparse
import SocketServer

class wsHandler(SocketServer.BaseRequestHandler):

    def getSecKey(self, key):
	GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11' # This is a number specified by the standard (do not change)
	return b64encode(sha.new(key+GUID).digest()) # Concatenate the key and GUID to get the secret hash

    def httpparse(self, headers):
	return dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", headers)) 

    def datahandler(self, data):
	try: # If there is http data, parse that
	    data2 = self.httpparse(data)
	    if data2['Upgrade'].lower()=='websocket':
		return self.wsug(data2) # if the client is looking for websocket verification, give it to them
	except KeyError:
	    return wsparse(data)

    def wsug(self, data):
	response = [
		     'HTTP/1.1 101 Switching Protocols',
		     'Connection: Upgrade',
		     'Upgrade: WebSocket',
		     'Sec-WebSocket-Accept: %s' % self.getSecKey(data['Sec-WebSocket-Key'])
		   ]
	ret='\r\n'.join(response)+'\r\n'*2
	return ret

    def handle(self):
	
	while True:
	    data = self.request.recv(1024)
	    rdata = self.datahandler(data)
	    if data[:3].lower() == 'get':
		self.request.sendall(rdata)
	    elif rdata['opcode'] == '0x8':
		self.request.close()
		break
	    elif rdata['opcode'] == '0x1':
		print rdata['text']
    
    def finish(self):
	
	print "Closed connection from %s:%d" % (self.client_address[0] , self.client_address[1])


    def setup(self):
	
	print "Opened connection from %s:%d" % (self.client_address[0] , self.client_address[1])

if __name__ == '__main__':
    host, port = 'localhost' , 8080

    server = SocketServer.TCPServer((host, port), wsHandler)
    server.serve_forever()
