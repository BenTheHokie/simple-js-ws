#!/usr/bin/env python
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
    for i in range(len(plencr)):
        pldecr.append(plencr[i] ^ rdict['mask'][i % 4]) # unencrypt using XOR decryption with the mask
    rdict['decrypted'] = '0x'+''.join([ hex(i)[2:] for i in pldecr ])

    if rdict['opcode'] == '0x1':
	rdict['text'] = ''.join([chr(i) for i in pldecr]) # convert to text

    return rdict
