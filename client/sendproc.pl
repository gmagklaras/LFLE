#!/usr/bin/perl -w

#Copyright (C) 2014-2020 Georgios Magklaras
#Steelcyber Scientific

use strict;

use Net::OpenSSH;
use IO::File;
use Time::HiRes qw(usleep clock_gettime gettimeofday clock_getres CLOCK_REALTIME ITIMER_REAL ITIMER_VIRTUAL ITIMER_PROF ITIMER_REALPROF);

my $sdelay=300000;
my $pspid="$$";

#Some essential sanity checks

#Does the LUARM clientauthentication file exist?
die "sendproc Error: I cannot start because I cannot find the LUARM client authentication file.\n Has the LUARM client being registered with lucreg.pl? \n" if (!(-e "./.lcaf.dat"));

#Open the authentication file and get the credentials
open(AUTH, "<","./.lcaf.dat");
my $authdata=<AUTH>;
close(AUTH);
my @authdata=split "#",$authdata;
my $status=shift @authdata;
my $username=shift @authdata;
my $password=shift @authdata;
my @serverdata=split ":",$status;
my $s1=shift @serverdata;
my $server=shift @serverdata;

#Get a list of the LUARM scanned proc entries
opendir(DIR, "/dev/shm") || die "sendproc Error: can't opendir /dev/shm: $!";
my @ftscp = grep { /^[1-9][0-9]*.proc/  } readdir(DIR);
closedir(DIR);


my $ssh = Net::OpenSSH->new($server, user => $username, password => $password );
$ssh->error and die "sendproc Error: Could not establish SSH connection to the LUARM v2 server $server:". ssh->error;

#And now attempt to scp them to the server
foreach my $myfile (@ftscp) {
		$ssh->scp_put({quiet=>0}, "/dev/shm/$myfile", "/home/$username/");
	}
	
#Now that the files are copied to the LUARM server, delete them from /dev/shm to free up valuable RAM
foreach my $myfile (@ftscp) {
		unlink "/dev/shm/$myfile";
	}
	
#Now copy all the net files
opendir(DIR, "/dev/shm") || die "sendproc Error: can't opendir /dev/shm: $!";
my @ftscpnet = grep { /^[1-9][0-9]*.net/  } readdir(DIR);
closedir(DIR);
	
foreach my $mynet (@ftscpnet) {
		$ssh->scp_put({quiet=>0}, "/dev/shm/$mynet", "/home/$username/");
	}
	
foreach my $myprocessednet (@ftscpnet) {
		unlink "/dev/shm/$myprocessednet";
	}
		
#$ssh->login($username,$password);

#$ssh->cmd("ls -la");
