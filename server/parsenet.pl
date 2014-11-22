#!/usr/bin/perl -w

# parsenet.pl: A LUARM v2 server script that parses the network endpoint 
# entries and populates the netinfo RDBMS table of the ITPSLschema.
# Note: This script should be run by the management scripts AFTER
#      the execution of the parseproc.pl. Reason: It relies on the
#      /proc data to cross reference the pid from the inode number in
#      /proc/net/tcp(6).
# By George Magklaras@steelcyber scientific

use strict;
#use warnings;
use Data::Dumper;
use Digest::SHA qw(sha1 sha1_hex sha256_hex);
use Digest::MD5 qw(md5 md5_hex md5_base64);
use DBI;
use Time::HiRes qw(usleep clock_gettime gettimeofday clock_getres CLOCK_REALTIME ITIMER_REAL ITIMER_VIRTUAL ITIMER_PROF ITIMER_REALPROF);
use Carp;
use Scalar::Util;

#Hash that regexps the structure of the /dev/net/tcp(6) and 
#/dev/net/udp(6) files
my %regexp = ( tcp => qr/^\s*
                         (\d+):\s                                     # sl                        -  0
                         ([\dA-F]{8}(?:[\dA-F]{24})?):([\dA-F]{4})\s  # local address and port    -  1 &  2
                         ([\dA-F]{8}(?:[\dA-F]{24})?):([\dA-F]{4})\s  # remote address and port   -  3 &  4
                         ([\dA-F]{2})\s                               # st                        -  5
                         ([\dA-F]{8}):([\dA-F]{8})\s                  # tx_queue and rx_queue     -  6 &  7
                         (\d\d):([\dA-F]{8}|F{9,}|1AD7F[\dA-F]{6})\s  # tr and tm->when           -  8 &  9
                         ([\dA-F]{8})\s+                              # retrnsmt                  - 10
                         (\d+)\s+                                     # uid                       - 11
                         (\d+)\s+                                     # timeout                   - 12
                         (\d+)\s+                                     # inode                     - 13
                         (\d+)\s+                                     # ref count                 - 14
                         ((?:[\dA-F]{8}){1,2})                        # memory address            - 15
                         (?:
                             \s+
                             (\d+)\s+                                 # retransmit timeout        - 16
                             (\d+)\s+                                 # predicted tick            - 17
                             (\d+)\s+                                 # ack.quick                 - 18
                             (\d+)\s+                                 # sending congestion window - 19
                             (-?\d+)                                  # slow start size threshold - 20
                         )?
                         \s*
                         (.*)                                         # more                      - 21
                         $
                        /xi,

               udp => qr/^\s*
                         (\d+):\s                                     # sl                        -  0
                         ([\dA-F]{8}(?:[\dA-F]{24})?):([\dA-F]{4})\s  # local address and port    -  1 &  2
                         ([\dA-F]{8}(?:[\dA-F]{24})?):([\dA-F]{4})\s  # remote address and port   -  3 &  4
                         ([\dA-F]{2})\s                               # st                        -  5
                         ([\dA-F]{8}):([\dA-F]{8})\s                  # tx_queue and rx_queue     -  6 &  7
                         (\d\d):([\dA-F]{8}|F{9,}|1AD7F[\dA-F]{6})\s  # tr and tm->when           -  8 &  9
                         ([\dA-F]{8})\s+                              # retrnsmt                  - 10
                         (\d+)\s+                                     # uid                       - 11
                         (\d+)\s+                                     # timeout                   - 12
                         (\d+)\s+                                     # inode                     - 13
                         (\d+)\s+                                     # ref count                 - 14
                         ((?:[\dA-F]{8}){1,2})                        # memory address            - 15
                         (?:
                             \s+
                             (\d+)                                    # drops                     - 16
                         )?
                         \s*
                         (.*)                                         # more                      - 17
                         $
                        /xi
             );
             
#Get the list of database userids
my @authinfo=getdbauth();
my ($dbusername,$dbname,$dbpass,$hostname);

foreach my $dbentry (@authinfo) {
	($dbusername,$dbname,$dbpass,$hostname)=split("," , $dbentry);
	}
my $datasource="DBI:mysql:$dbname:$hostname:3306";
my $lhltservh=DBI->connect ($datasource, $dbusername, $dbpass, {RaiseError => 1, PrintError => 1});
my $SQLh=$lhltservh->prepare("SELECT ciduser FROM lhltable");
$SQLh->execute();
my @cidhits=$SQLh->fetchrow_array();
$SQLh->finish();

#For every detected user account get the *.proc files, parse them,populate 
#the RDBMS and eventually delete them to save space
foreach my $user (@cidhits) {
	opendir(DIR, "/home/$user") || die "parsenet.pl Error: can't open user directory /home/$user: $!";
	my @mynetfiles = sort grep { /^[1-9][0-9]*.net/  } readdir(DIR);
	#Debug
	print "mynetfiles array is: @mynetfiles \n";

	#If there are are new files, hit the LHLT db to find the dbname for that user
	my ($dbusername,$dbname,$dbpass,$hostname);
	foreach my $dbentry (@authinfo) {
		($dbusername,$dbname,$dbpass,$hostname)=split("," , $dbentry);
	}
	my $datasource="DBI:mysql:$dbname:$hostname:3306";
	my $lhltservh=DBI->connect ($datasource, $dbusername, $dbpass, {RaiseError => 1, PrintError => 1});
	my $SQLh=$lhltservh->prepare("SELECT cid FROM lhltable WHERE ciduser='$user' ");
	$SQLh->execute();
	my @dbnamehits=$SQLh->fetchrow_array();
	$SQLh->finish();
	my $ldb=$dbnamehits[0];
	#Remove the "-" from the dbname
	$ldb =~ s/-//g;
	print "Dbname is $ldb \n";
	
	#Connect to the right host db
	my $userdb="DBI:mysql:$ldb:$hostname:3306";
	my $hostservh=DBI->connect ($userdb, $dbusername, $dbpass, {RaiseError => 1, PrintError => 1});
	
	#Start the process of parsing network endpoints
	foreach my $fitopr (@mynetfiles) {
		open(FHL, "<", "/home/$user/$fitopr");
		my @lines=<FHL>;
		my ($tcpdata,$tcpv6data,$udpdata,$udpv6data);
		foreach my $line (@lines) {
			#Strip the \n at the end of the line
			chomp $line;
			($tcpdata,$tcpv6data,$udpdata,$udpv6data)=split("#", $line);
		} #end of foreach my $line (@lines) 
		
	} #end of foreach my $fitopr (@mynetfiles)
	
} #end of foreach my $user (@cidhits)



#Subroutines here
sub getdbauth {
	#DBAUTH path hardwired only on the server side
	unless(open DBAUTH, "<./.adb.dat") {
			die "lusreg Error:getdbauth: Could not open the .adb.dat file due to: $!";
		}

	my @localarray;	
	
	while (<DBAUTH>) {
		my $dbentry=$_;
		chomp($dbentry);
		push(@localarray, $dbentry);
	}

	return @localarray;	
	
} #end of getdbauth() 

sub timestamp {
	#get the db authentication info
        my @authinfo=getdbauth();
        my ($username,$dbname,$dbpass,$hostname);

        foreach my $dbentry (@authinfo) {
                ($username,$dbname,$dbpass,$hostname)=split("," , $dbentry);
        }

        my $datasource="DBI:mysql:$dbname:$hostname:3306";
        my $itpslservh=DBI->connect ($datasource, $username, $dbpass, {RaiseError => 1, PrintError => 1});

        my $SQLh=$itpslservh->prepare("select DATE_FORMAT(NOW(), '%Y-%m-%d-%k-%i-%s')");
        $SQLh->execute();

	my @timearray=$SQLh->fetchrow_array();
	my ($year,$month,$day,$hour,$min,$sec)=split("-",$timearray[0]);
	$SQLh->finish();
	return ($year,$month,$day,$hour,$min,$sec);
} #end of timestamp

sub _hex2ip {
    my $bin = pack "C*" => map hex, $_[0] =~ /../g;
    my @l = unpack "L*", $bin;
    if (@l == 4) {
        return join ':', map { sprintf "%x:%x", $_ >> 16, $_ & 0xffff } @l;
    }
    elsif (@l == 1) {
        return join '.', map { $_ >> 24, ($_ >> 16 ) & 0xff, ($_ >> 8) & 0xff, $_ & 0xff } @l;
    }
    else { die "internal error: bad hexadecimal encoded IP address '$_[0]'" }
}
