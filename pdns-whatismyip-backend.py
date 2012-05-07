#!/usr/bin/python
#
"""
PowerDNS pipe backend that will return the IP of the one querying
	no matter what was asked. ;)

pdns.conf example:

launch=pipe
pipe-command=/etc/powerdns/pdns-whatismyip-backend.py
pipe-timeout=500
pipebackend-abi-version=2

### LICENSE ###

The MIT License

Copyright (c) 2010 Stefan "ZaphodB" Schmidt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""
import sys, os
import syslog
import time
import netaddr

syslog.openlog(os.path.basename(sys.argv[0]), syslog.LOG_PID)
syslog.syslog('starting up')

DNS    = 'shinjuku.zaphods.net'  # this nameserver
EMAIL  = 'zaphodb.zaphods.net'  # this nameserver administrator
TTL    = 1                    # time to live
DOMAIN = 'ip.zap.li'	# the domain we serve the record under

def parse(fd, out):
    line = fd.readline().strip()
    if not line.startswith('HELO'):
        print >>out, 'FAIL'
        out.flush()
        syslog.syslog('received "%s", expected "HELO"' % (line,))
        sys.exit(1)
    else:
    	print >>out, 'OK\t%s ready' % (os.path.basename(sys.argv[0]),)
        out.flush()
    	syslog.syslog('received HELO from PowerDNS')

    while True:
        line = fd.readline().strip()
        if not line:
            BREAK

        #syslog.syslog('<<< %s' % (line,))
	#print >>out, 'LOG\tgot line: %s' % line
        request = line.split('\t')
	if len(request) == 2:
		print >>out, 'DATA\t%s\t%s\tSOA\t%d\t1\t%s %s %s' % \
			(DOMAIN, 'IN', TTL, DNS, EMAIL, time.strftime('%Y%m%d%H'))
		print >>out, 'END'
        	out.flush()
		continue
        elif len(request) < 7:
		print >>out, 'LOG\tPowerDNS sent unparsable line'
		print >>out, 'FAIL'
        	out.flush()
		continue
	else:
		try:
	        	kind, qname, qclass, qtype, qid, their_ip, our_ip = request
			#debug
			#print >>out, 'LOG\tPowerDNS sent qname>>%s<< qtype>>%s<< qclass>>%s<< qid>>%s<< our_ip>>%s<< their_ip>>%s<<' % (qname, qtype, qclass, qid, our_ip, their_ip)
			if qtype in ['TXT', 'ANY'] and qname == DOMAIN:
				print >>out, 'DATA\t%s\t%s\tTXT\t%d\t1\t\"Your IP Address or that of your recursive nameserver is: %s\"' % \
			                       		(DOMAIN, qclass, TTL, their_ip)
			if qtype in ['NS', 'ANY'] and qname == DOMAIN:
				print >>out, 'DATA\t%s\t%s\tNS\t%d\t1\t%s' % \
					(DOMAIN, qclass, TTL, DNS)
			if qtype in ['A', 'ANY'] and qname == DOMAIN:
				try:
					ip=netaddr.IPAddress(their_ip)
					print >>out, 'DATA\t%s\t%s\tA\t%d\t1\t%s' % \
						(DOMAIN, qclass, TTL, ip.ipv4())
				except:
					pass
			if qtype in ['AAAA', 'ANY'] and qname == DOMAIN:
				try:
					ip=netaddr.IPAddress(their_ip)
					print >>out, 'DATA\t%s\t%s\tAAAA\t%d\t1\t%s' % \
						(DOMAIN, qclass, TTL, ip.ipv6())
				except:
					pass
			if qtype in ['SOA', 'ANY'] and qname == DOMAIN:
				print >>out, 'DATA\t%s\t%s\tSOA\t%d\t1\t%s %s %s 10800 3600 604800 3600' % \
			                       		(DOMAIN, qclass, TTL, DNS, EMAIL, time.strftime('%Y%m%d%H'))
		except:
			pass
	print >>out, 'END'
        out.flush()
	continue

    syslog.syslog('terminating')
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(parse(sys.stdin, sys.stdout))
