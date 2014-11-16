#!/usr/bin/perl -w

use strict;

use IO::File;
use Time::HiRes qw(usleep clock_gettime gettimeofday clock_getres CLOCK_REALTIME ITIMER_REAL ITIMER_VIRTUAL ITIMER_PROF ITIMER_REALPROF);

my $sdelay=400000;
my $netpid="$$";

while (1==1) {
	
	my $timeref;
	open(TMR, "<","/proc/uptime");
	my @timerefa=<TMR>;
	close(TMR);

	my @timerefstr=split " ", $timerefa[0];
	$timeref=$timerefstr[0];
	$timeref=~ tr/'.'//d;
	
	#Get the IPv4 endpoints
	open(TCPFD, "<","/proc/net/tcp");
	my @tcpv4=<TCPFD>;
	close(TCPFD);
	open(UDPFD, "<","/proc/net/udp");
	my @udpv4=<UDPFD>;
	close(UDPFD);

	#Get the IPv6 endpoints
	open(TCPFD6, "<","/proc/net/tcp6");
        my @tcpv6=<TCPFD6>;
        close(TCPFD6);
        open(UDPFD6, "<","/proc/net/udp6");
        my @udpv6=<UDPFD6>;
        close(UDPFD6);
	
	open WRDNET , ">", "/dev/shm/$timeref.net";
	select WRDNET;
	print "@tcpv4#@tcpv6#@udpv4#@udpv6";
	close(WRDNET);
	
	usleep($sdelay);
} #end of infinite  while loop
