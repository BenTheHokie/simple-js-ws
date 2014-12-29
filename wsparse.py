#!/usr/bin/env python
import binascii
from random import getrandbits

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


def wsparse(data):
    hdata = binascii.b2a_hex(data) # get the hex data
    bdata = hextobin(hdata) # convert to binary
    rdict = { 'rawdata' :   data ,
	      'bindata' :   bdata ,
	      'mask' :	    [] 
	    }
    
    rdict.update({ 
	      'fin':	    bool(bdata[0]),
	      'rsv':	    bdata[1:4],
	      'opcode':	    hex(int(bdata[4:8],2))
		 })
    
    mask = bool(bdata[8]=='1')

    plen = int(bdata[9:16],2)
    if plen < 126:
	rdict.update({ 'plen' : plen })
	bdata = bdata[16:]
    elif plen == 126:
	rdict.update({ 'plen' : int(bdata[16:32],2) })
	bdata = bdata[32:]
    else:
	rdict.update({ 'plen' : int(bdata[16:80],2) })
	bdata = bdata[80:]

    if mask:
	for i in range(4):
	    rdict['mask'].append(int(bdata[ i*8 : (i+1)*8 ],2))
	bdata = bdata[32:]

    rdict['bpl'] = bdata[:] # Binary payload

    plencr = [] # payload encrypted
    for i in range(rdict['plen']):
        plencr.append(rdict['bpl'][i*8:(i+1)*8]) # chop the payload into octets and add them to plencr

    plencr = [int(b,2) for b in plencr] # convert to binary
    
    pldecr = [] # payload decrypted
    if mask:
	for i in range(len(plencr)):
	    pldecr.append(plencr[i] ^ rdict['mask'][i % 4]) # unencrypt using XOR decryption with the mask
    else:
	pldecr = plencr[:]
    rdict['decrypted'] = '0x'+''.join([ hex(i)[2:] for i in pldecr ])

    if rdict['opcode'] in ('0x1','0x8'):
	rdict['text'] = ''.join([chr(i) for i in pldecr]) # convert to text

    return rdict


def wsunparse(data):

    final = ''

    mask = []
    if 'mask' in data.keys():
	from numbers import Number
	if type(data['mask'] == list) and len(data['mask']) == 4:
	    mask = data['mask']
	elif data['mask']==True and (isinstance(data['mask'] , Number) or isinstance(data['mask'] , bool)):
	    for i in range(4):
		mask.append(int(getrandbits(8))) # Generate some random bits for the mask
    
    pl = ''

    if data['opcode'] in ('0x8',8):
	final += '\x88' # fin, close
    else:
	final += '\x81' # fin, text

    plen = len(data['payload'])
    if plen > 125:
	raise

    if mask:
	itext = [ord(a) for a in list(data['payload'])]
	for c in range(len(itext)):
	    pl += chr(itext[c] ^ mask[c % 4])
	final += chr(128 + plen) # turn on mask bit
	final += ''.join([chr(c) for c in mask])
    else:
	pl = data['payload']
	final += chr(plen)
    
    final += pl

    print final
    return final
