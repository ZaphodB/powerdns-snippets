#!/usr/bin/python
#
"""
PowerDNS pipe backend for generating reverse DNS entries and their
forward lookup.

pdns.conf example:

launch=pipe
pipe-command=/usr/local/sbin/pipe-local-ipv6-wrapper
pipe-timeout=500

### LICENSE ###

The MIT License

Copyright (c) 2009 Wijnand "maze" Modderman
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
import re
import syslog
import time
import netaddr

syslog.openlog(os.path.basename(sys.argv[0]), syslog.LOG_PID)
syslog.syslog('starting up')

DNS    = 'mandelbrot.zaphods.net'  # this nameserver
EMAIL  = 'zaphodb.zaphods.net'  # this nameserver administrator
TTL    = 300                    # time to live
RANGES = {                      # ranges we serve
	netaddr.IPNetwork('2001:67c:1400:1220::/56'): {
        	'forward' : 'ipv6.zaphods.net',
		'domain' : '0.0.2.2.1.0.0.4.1.c.7.6.0.1.0.0.2.ip6.arpa',
		'dns' : 'mandelbrot.zaphods.net',
		'email' : 'zaphodb.zaphods.net',
		'ttl' : 300,
		'version' : 6,
		'nameserver' : [
			'mandelbrot.zaphods.net',
			'shinagawa.zaphods.net',
		],
	},
	netaddr.IPNetwork('2001:67c:320::/48'): {
		'forward' : 'ipv6.congress.ccc.de',
		'domain' : '0.2.3.0.c.7.6.0.1.0.0.2.ip6.arpa',
		'dns' : 'ns1.congress.resolvt.net',
		'email' : 'hostmaster.resolvt.net',
		'ttl' : 300,
		'version' : 6,
		'nameserver' : [
			'ns1.congress.resolvt.net',
			'ns2.congress.resolvt.net',
			'ns3.congress.resolvt.net',
		],
	},
	netaddr.IPNetwork('81.163.0.0/16'): {
		'forward' : 'ipv4.congress.ccc.de',
		'domain' : '163.81.in-addr.arpa',
		'dns' : 'ns1.congress.resolvt.net',
		'email' : 'hostmaster.resolvt.net',
		'ttl' : 300,
		'version' : 4,
		'nameserver' : [
			'ns1.congress.resolvt.net',
			'ns2.congress.resolvt.net',
			'ns3.congress.resolvt.net',
		],
	},
    }
DIGITS = '0123456789abcdefghijklmnopqrstuvwxyz'


def base36encode(n):
    s = ''
    while True:
        n, r = divmod(n, len(DIGITS))
        s = DIGITS[r] + s
        if n == 0:
            break
    return s

def base36decode(s):
    n, s = 0, s[::-1]
    for i in xrange(0, len(s)):
        r = DIGITS.index(s[i])
        n += r * (len(DIGITS) ** i)
    return n



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

    lastnet=0
    while True:
        line = fd.readline().strip()
        if not line:
            break

        #syslog.syslog('<<< %s' % (line,))
	#print >>out, 'LOG\tline: %s' % line

        request = line.split('\t')
	if request[0] == 'AXFR':
		if not lastnet == 0:
			print >>out, 'DATA\t%s\t%s\tSOA\t%d\t-1\t%s %s %s 10800 3600 604800 3600' % \
				(lastnet['forward'], 'IN', lastnet['ttl'], lastnet['dns'], lastnet['email'], time.strftime('%Y%m%d%H'))
			lastnet=lastnet
			for ns in lastnet['nameserver']:
				print >>out, 'DATA\t%s\t%s\tNS\t%d\t-1\t%s' % \
					(lastnet['forward'], 'IN', lastnet['ttl'], ns)
		print >>out, 'END'
        	out.flush()
		continue
        if len(request) < 6:
            print >>out, 'LOG\tPowerDNS sent unparsable line'
            print >>out, 'FAIL'
            out.flush()
            continue


        try:
		kind, qname, qclass, qtype, qid, ip = request
	except:
		kind, qname, qclass, qtype, qid, ip, their_ip = request
	#debug
	#print >>out, 'LOG\tPowerDNS sent qname>>%s<< qtype>>%s<< qclass>>%s<< qid>>%s<< ip>>%s<<' % (qname, qtype, qclass, qid, ip)

        if qtype in ['AAAA', 'ANY'] and qname.startswith('node-'):
	    #print >>out, 'LOG\twe got a AAAA query'
            for range, key in RANGES.iteritems():
                if qname.endswith('.%s' % (key['forward'],)) and key['version'] == 6:
                    node = qname[5:].replace('.%s' % (key['forward'],), '')
                    try:
                        node = base36decode(node)
                    except ValueError:
                        node = None
                    if node:
                        ipv6 = netaddr.IPAddress(long(range.value) + long(node))
                        print >>out, 'DATA\t%s\t%s\tAAAA\t%d\t-1\t%s' % \
                            (qname, qclass, key['ttl'], ipv6)
		    break
        if qtype in ['A', 'ANY'] and qname.startswith('node-'):
	    #print >>out, 'LOG\twe got a A query'
            for range, key in RANGES.iteritems():
                if qname.endswith('.%s' % (key['forward'],)) and key['version'] == 4:
                    node = qname[5:].replace('.%s' % (key['forward'],), '')
                    try:
                        node = base36decode(node)
                    except ValueError:
                        node = None
                    if node:
                        ipv4 = netaddr.IPAddress(long(range.value) + long(node))
                        print >>out, 'DATA\t%s\t%s\tA\t%d\t-1\t%s' % \
                            (qname, qclass, key['ttl'], ipv4)
		    break

        if qtype in ['PTR', 'ANY'] and qname.endswith('.ip6.arpa'):
	    #print >>out, 'LOG\twe got a PTR query'
            ptr = qname.split('.')[:-2][::-1]
            ipv6 = ':'.join(''.join(ptr[x:x+4]) for x in xrange(0, len(ptr), 4))
            try:
		ipv6 = netaddr.IPAddress(ipv6)
	    except:
		ipv6 = netaddr.IPAddress('::')
            for range, key in RANGES.iteritems():
		#debug
		#print >>out, 'LOG\tPowerDNS sent qname>>%s<< qtype>>%s<< qclass>>%s<< TTL>>%s<<' % (qname, qtype, qclass, TTL)
                if ipv6 in range:
                    node = ipv6.value - range.value
                    node = base36encode(node)
                    print >>out, 'DATA\t%s\t%s\tPTR\t%d\t-1\tnode-%s.%s' % \
                        (qname, qclass, key['ttl'], node, key['forward'])
		    break

        if qtype in ['PTR', 'ANY'] and qname.endswith('.in-addr.arpa'):
	    #print >>out, 'LOG\twe got a PTR query'
            ptr = qname.split('.')[:-2][::-1]
	    ipv4='.'.join(''.join(ptr[x:x+1]) for x in xrange(0, len(ptr), 1))
            try:
		ipv4 = netaddr.IPAddress(ipv4)
	    except:
		ipv4 = netaddr.IPAddress('127.0.0.1')
            for range, key in RANGES.iteritems():
		#debug
		#print >>out, 'LOG\tPowerDNS sent qname>>%s<< qtype>>%s<< qclass>>%s<< TTL>>%s<<' % (qname, qtype, qclass, TTL)
                if ipv4 in range:
                    node = ipv4.value - range.value
                    node = base36encode(node)
                    print >>out, 'DATA\t%s\t%s\tPTR\t%d\t-1\tnode-%s.%s' % \
                        (qname, qclass, key['ttl'], node, key['forward'])
		    break

#        if qtype in ['SOA', 'ANY'] and qname.endswith('.ip6.arpa'):
#	    #print >>out, 'LOG\twe got a SOA query for %s' % qname
#            ptr = qname.split('.')[:-2][::-1]
#            ipv6 = ':'.join(''.join(ptr[x:x+4]) for x in xrange(0, len(ptr), 4))
#            try:
#		ipv6 = netaddr.IPAddress(ipv6)
#	    except:
#		ipv6 = netaddr.IPAddress('::')
#            for range, key in RANGES.iteritems():
#		#print >>out, 'LOG\tin for'
#		#print >>out, 'LOG\trange is %s' % range
#		#print >>out, 'LOG\tkey is %s' % key
#		if qname == key['domain']:
#			print >>out, 'DATA\t%s\t%s\tSOA\t%d\t-1\t%s %s %s 10800 3600 604800 3600' % \
#				(key['domain'], qclass, key['ttl'], key['dns'], key['email'], time.strftime('%Y%m%d%H'))
#			lastnet=key
#			break
#		if ipv6 in range:
#			#print >>out, 'LOG\tipv6 is in range'
#                    	print >>out, 'DATA\t%s\t%s\tSOA\t%d\t-1\t%s %s %s 10800 3600 604800 3600' % \
#                       		(key['domain'], qclass, key['ttl'], key['dns'], key['email'], time.strftime('%Y%m%d%H'))
#			lastnet=key
#			break
#	#print >>out, 'LOG\twe reached the end of IF clauses'
#
#        if qtype in ['SOA', 'ANY'] and qname.endswith('.in-addr.arpa'):
#	    #print >>out, 'LOG\twe got a SOA query for %s' % qname
#            ptr = qname.split('.')[:-2][::-1]
#	    ipv4='.'.join(''.join(ptr[x:x+1]) for x in xrange(0, len(ptr), 1))
#            try:
#		ipv4 = netaddr.IPAddress(ipv4)
#	    except:
#		ipv4 = netaddr.IPAddress('127.0.0.1')
#            for range, key in RANGES.iteritems():
#		#print >>out, 'LOG\tin for'
#		#print >>out, 'LOG\trange is %s' % range
#		#print >>out, 'LOG\tkey is %s' % key
#		if qname == key['domain']:
#			print >>out, 'DATA\t%s\t%s\tSOA\t%d\t-1\t%s %s %s 10800 3600 604800 3600' % \
#				(key['domain'], qclass, key['ttl'], key['dns'], key['email'], time.strftime('%Y%m%d%H'))
#			lastnet=key
#			break
#		if ipv4 in range:
#			#print >>out, 'LOG\tipv4 is in range'
#                    	print >>out, 'DATA\t%s\t%s\tSOA\t%d\t-1\t%s %s %s 10800 3600 604800 3600' % \
#                       		(key['domain'], qclass, key['ttl'], key['dns'], key['email'], time.strftime('%Y%m%d%H'))
#			lastnet=key
#			break
#	#print >>out, 'LOG\twe readed the end of IF clauses'

	if qtype in ['SOA', 'ANY', 'NS']:
		for range, key in RANGES.iteritems():
			#print >>out, 'LOG\tkey domain: %s' % key['domain']
			#print >>out, 'LOG\tkey forward: %s' % key['forward']
			#print >>out, 'LOG\tqname: %s' % qname
			if qname == key['domain']:
				if not qtype == 'NS':
					print >>out, 'DATA\t%s\t%s\tSOA\t%d\t-1\t%s %s %s 10800 3600 604800 3600' % \
						(key['domain'], qclass, key['ttl'], key['dns'], key['email'], time.strftime('%Y%m%d%H'))
					lastnet=key
				if qtype in ['ANY', 'NS']:
					for ns in key['nameserver']:
						print >>out, 'DATA\t%s\t%s\tNS\t%d\t-1\t%s' % \
							(key['domain'], qclass, key['ttl'], ns)
				break
			elif qname == key['forward']:
				if not qtype == 'NS':
					print >>out, 'DATA\t%s\t%s\tSOA\t%d\t-1\t%s %s %s 10800 3600 604800 3600' % \
						(key['forward'], qclass, key['ttl'], key['dns'], key['email'], time.strftime('%Y%m%d%H'))
					lastnet=key
				if qtype in ['ANY', 'NS']:
					for ns in key['nameserver']:
						print >>out, 'DATA\t%s\t%s\tNS\t%d\t-1\t%s' % \
							(key['forward'], qclass, key['ttl'], ns)
				break

        print >>out, 'END'
        out.flush()

    syslog.syslog('terminating')
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(parse(sys.stdin, sys.stdout))
