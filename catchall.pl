#!/usr/bin/perl -w
# PowerDNS Coprocess backend
# in pdns.conf use:
# launch=pipe
# pipe-command=/path/to/catchall.pl
# pipe-timeout=1000
# pipebackend-abi-version=2

use strict;
use warnings;
$|=1;					# no buffering

my $webserverip="4.3.2.1";
my $nameserver="ns1.example.com";
my $hostmaster="hostmaster.example.com";
my $line=<>;
chomp($line);
unless($line eq "HELO\t2") {
	print "FAIL\n";
	<>;
	exit;
}
print "OK	Catchall fireing up!\n";	# print our banner
my @last_query=();
my ($type,$qname,$qclass,$qtype,$id,$ip,$lip);
LINE: while(<>)
{
	chomp();
	my @arr=split(/\t/);
	if((defined $arr[0])&&($arr[0] eq "PING")) {
		print "LOG	Catchall is still alife!\n";
		print "END\n";
		next LINE;
	}
	if((defined $arr[0])&&($arr[0] eq "AXFR")) {
		print "END\n";
		next LINE;
	}
	if((@arr)&&(@arr<7)) {
		print "LOG	PowerDNS sent too few arguments, wrong ABI Version 1 in config?\n";
		print "FAIL\n";
		next LINE;
	}
	($type,$qname,$qclass,$qtype,$id,$ip,$lip)=@arr;
	if((defined $type)&&(defined $qname)&&(defined $qclass)&&(defined $qtype)&&(defined $id)&&(defined $ip)&&(defined $lip)) {
	} else {
		print "FAIL\n";
		next LINE;
	}
	if($type ne "Q") {
		print "END\n";
		next LINE;
	}
	if((defined $type)&&(defined $qname)&&(defined $qclass)&&(defined $qtype)&&(defined $id)&&(defined $ip)&&(defined $lip)) {
		if(($qtype eq "SOA")||($qtype eq "ANY")) {
			print "DATA	$qname	$qclass	SOA	3600	-1	$nameserver	$hostmaster 2008080300 1800 3600 604800 3600\n";
		}
		if(($qtype eq "A")||($qtype eq "ANY")) {
			print "DATA	$qname	IN	A	3600	1	$webserverip\n";
		}
	} else {
		print "LOG	ERROR - some parts are missing - this should not happen!\n";
	}
	print "END\n";
	next LINE;
}
