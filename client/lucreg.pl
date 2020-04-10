#!/usr/bin/perl -w

#Copyright (C) 2014-2020 Georgios Magklaras
#Steelcyber Scientific
#Registers a LUARM v2 client to a LUARM v2 server

use strict;
use Net::SSH::Perl;
use Net::SCP qw(scp iscp);
use Getopt::Long;
use Time::HiRes qw(usleep clock_gettime gettimeofday clock_getres CLOCK_REALTIME
 ITIMER_REAL ITIMER_VIRTUAL ITIMER_PROF ITIMER_REALPROF);

my $sdelay=10000000; #10 secs


#Essential sanity checks
my @whoami=getpwuid($<);
die "lucreg Error:You should execute this program ONLY with root privileges. You are not root.\n"
if ($whoami[2]!=0 && $whoami[3]!=0); 

sub dispusage {
	print "Usage: 	lucreg --server SERVER_DNS_NAME_OR_IP_ADDRESS --pass PASSWORD [--help] \n";
	print "Example:	lucreg --server myserver.mydomain.com --pass Saf3PaSS80rD# \n";
	exit;
}

my $server;
my $pass;
my $helpflag;
my $username="luarmreg";

GetOptions("server=s" => \$server,
	   "pass=s" => \$pass,
	   "help" => \$helpflag );

if ($helpflag) {
	dispusage;
}

if (! (defined($server))) {
        print "lucreg Error: The --server switch is not defined. I shall exit and do nothing! \n";
        dispusage;
}

if (! (defined($pass))) {
        print "lucreg Error: You did not specify a password with the --pass switch. I shall exit and do nothing! \n";
        dispusage;
}

#Get the system UUID
my $uuidstr=`dmidecode --type system | grep UUID | cut -d":" -f2`;
$uuidstr=~ s/(^\s+|\s+$)//g;

#Get the timeref
open(TMR, "<","/proc/uptime");
my @timerefa=<TMR>;
close(TMR);
my @timerefstr=split " ", $timerefa[0];
my $timeref=$timerefstr[0];
$timeref=~ tr/'.'//d;

my $cidstr=$uuidstr . $timeref;

print "$cidstr \n";

#Generate the necessary RSA keys with passphrase the client ID string
system "ssh-keygen -q -t rsa -N $cidstr";

#Check that we have proper RSA key generation
die "lucreg Error:Could not generate RSA keys: $!\n" if (! (-e "/root/.ssh/id_rsa.pub")); 

#Read the Public RSA key
open(RSA, "<","/root/.ssh/id_rsa.pub");
my $rsapub=<RSA>;
close(RSA);

#Create the request file with all the necessary data
open(RQF, ">", "./request$cidstr.luarm") or die "lucreg Error: Cannot create the request file: $! \n";
select RQF;
print "$uuidstr#$cidstr#$rsapub";
close(RQF);

select STDOUT;

#Now send the request to the LUARM v2 server
#Connect to the LUARM v2  server
print "lucreg: OK. Connecting to the specified LUARM v2 server: $server to send our registration request. \n ";
my $scp=Net::SCP->new( {"host"=>$server, "user"=>$username} );
$scp->iscp("./request$cidstr.luarm", "$username\@$server:~/") or die $scp->{errstr};

print "lucreg: OK. Request sent successfully to server $server \n.";
#Wait a bit and keep attempting to obtain the response file from the server
do {{
	print "lucreg: Waiting for the LUARM v2 server $server to respond on our request...\n";
	usleep($sdelay);
	$scp->iscp("$username\@$server:~/response$cidstr.reg", "./");
}} until (-e "./response$cidstr.reg");  

#Now open the retrieved response file and inform of the outcome. 

open(RESP, "<","./response$cidstr.reg");
my $resp=<RESP>;
close(RESP);
my @respdata=split "#",$resp;
my $result=shift @respdata;
my $message=shift @respdata;
my $email=shift @respdata;

if ($result eq "Status:GRANTED") {
	print "##########################################################################\n";
	print "#lucreg: STATUS: OK. Client $cidstr  #\n";
	print "#was registered on LUARM server $server . # \n";
	print "##########################################################################\n";
	
	#In that case create the client authentication file
	open(AUTH, ">", "./.lcaf.dat") || die "lusreg Error: Cannot create the client authentication file: $! \n";
	select AUTH;
	#In the case of Status:Granted, $message is really the construid we need to SSH as and $email is the digest (password)
	print "Status:$server#$message#$email";
	close(AUTH);
	
  } else {
	  
	print "##########################################################################\n";
	print "#lucreg: STATUS: NOT OK. Client $cidstr  \n";
	print "#was denied registration, due to: $message #\n";
	print "#Please contact the LUARM v2 server administrator to resolve this.       #\n";
	print "##########################################################################\n";

}

#Eventually cleanup any left over request files
unlink glob "./*.luarm";



