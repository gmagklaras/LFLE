#!/usr/bin/perl -w

use strict;

use IO::File;
use Time::HiRes qw(usleep clock_gettime gettimeofday clock_getres CLOCK_REALTIME ITIMER_REAL ITIMER_VIRTUAL ITIMER_PROF ITIMER_REALPROF);

my $sdelay=300000;
my $sprocpid="$$";

while (1==1) {
opendir(DIR, "/proc") || die "can't opendir /proc: $!";
my @procs = grep { /^[1-9][0-9]*/  } readdir(DIR);
closedir(DIR);

my $timeref;

#Debug
#print "Processes are: @procs \n";

#Get the timeref
open(TMR, "<","/proc/uptime");
my @timerefa=<TMR>;
close(TMR);

my @timerefstr=split " ", $timerefa[0];

#print "timerefstr is: @timerefstr \n";
$timeref=$timerefstr[0];
#print "timeref is: $timeref\n";

$timeref=~ tr/'.'//d;

#print "$timeref is now: $timeref \n";
#Debug
#print "Pid is: $pspid. Time is: $timeref \n";

open WRD , ">", "/dev/shm/$timeref.proc";
foreach my $proc (@procs) {
	 open(CMD, "<","/proc/$proc/cmdline");
	 my $cmdline=<CMD>;
	 close(CMD);
	 if (!(defined $cmdline))  { $cmdline="--NOCMDARGENTRY--";}
	 open(STA, "<","/proc/$proc/status");
	 my @ppida=<STA>;
	 my @ppidstr=split ":", $ppida[5];
	 my $ppid=$ppidstr[1];
	 my @namea=split ":", $ppida[0];
	 my $name=$namea[1];
	 #Remove white space from $ppid and $name
	 $ppid=~ s/(^\s+|\s+$)//g;
	 $name=~ s/(^\s+|\s+$)//g;
	 my @struid=split ":", $ppida[7];
	 my @euid=split "\t", $struid[1];
	 my $uid=$euid[1];
	 close(STA);
	 opendir(FDD, "/proc/$proc/fd");
	 my @fds = grep { /^[1-9][0-9]*/  } readdir(FDD);
	 close(FDD);
	 my @openfiles;
	 foreach my $fd (@fds) {
		push(@openfiles,readlink"/proc/$proc/fd/$fd");
	} #end of foreach my $fd
    
    if ($#openfiles=='-1') {
		select WRD;
		print "$sprocpid###$proc###$ppid###$uid###$name###$cmdline###LUARMv2NOOPENFILES \n"; } 
		else { 
		select WRD;
		print "$sprocpid###$proc###$ppid###$uid###$name###$cmdline###@openfiles \n"; 
    }

	} #END OF foreach my $proc
	
	close(WRD);
	usleep($sdelay);
} #END OF while loop
