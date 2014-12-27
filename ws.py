#!/usr/bin/env python
import socket
import sha
from base64 import b64encode
import re
import binascii

def hextobin(hexval):
    '''
    Takes a string representation of hex data with
    arbitrary length and converts to string representation
    of binary.  Includes padding 0s
    '''
    thelen = len(hexval)*4
    binval = bin(int(hexval, 16))[2:]
    while ((len(binval)) < thelen):
        binval = '0' + binval
    return binval

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
	hdata = binascii.b2a_hex(data) # get the hex data
	bdata = hextobin(hdata) # convert to binary

	binval2=''
	for i in range(len(bdata)/4):
	    binval2+=bdata[i*4:(i+1)*4]+','
	ddict = {
		'FIN': bdata[0],
		'rsv1-3': bdata[1:4],
		'opcode': hex(int(bdata[4:8],2)), # opcodes See https://developer.mozilla.org/en-US/docs/WebSockets/Writing_WebSocket_servers
		'mask?': bdata[8], # boolean value of mask
		'plen': int(bdata[9:16],2), # payload length
		'mask': [ int(bdata[16:24],2) , int(bdata[24:32],2) , int(bdata[32:40],2) , int(bdata[40:48],2) ], # Mask values
		'payload': bdata[48:] # the payload is the remainder of the data
		}
	plencr=[] # payload encrypted
	for i in range(ddict['plen']):
	    plencr.append(ddict['payload'][i*8:(i+1)*8]) # chop the payload into octets and add them to plencr
	plencr=[int(b,2) for b in plencr] # convert to binary
	pldecr=[] # payload decrypted
	for i in range(len(plencr)):
	    pldecr.append(plencr[i]^ddict['mask'][i % 4]) # unencrypt using XOR decryption with the mask
	pltext=''.join([chr(i) for i in pldecr]) # convert to text
	print pltext

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

