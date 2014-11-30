stealthDNS
==========

A collection of tools that use DNS channels

The stager connects to and fetches an arbitrary binary from the CnC.
The binary to be executed is fetched in chunks as DNS query responses,
which are then re-assembled at the victim.

dnslib pydocs: https://bitbucket.org/paulc/dnslib/src
dnslib sample: https://gist.github.com/andreif/6069838
