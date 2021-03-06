#!/usr/bin/perl -w

#lusreg : Handles the LUARM client v2 registration requests
#Copyright (C) 2014-2020 Georgios Magklaras
#Steelcyber Scientific

use strict;

use Data::Dumper;
use DBI;
use IO::File;
use Time::HiRes qw(usleep clock_gettime gettimeofday clock_getres CLOCK_REALTIME ITIMER_REAL ITIMER_VIRTUAL ITIMER_PROF ITIMER_REALPROF);
use Digest::SHA qw(sha1 sha1_hex sha256_hex);
use Digest::MD5 qw(md5_hex);

my $sdelay=400000;
my $reghome="/home/luarmreg";
my $userhome="/home";

opendir(DIR, $reghome) || die "lusreg Error:can't open client registration directory: $!";
my @requests = grep { /^.*luarm$/ } readdir(DIR);
closedir(DIR);

foreach my $req (@requests) {
         open(REQ, "<","$reghome/$req");
         my $creq=<REQ>;
         close(REQ);
         my @reqdata=split "#",$creq;
         my $uuid=shift @reqdata;
         my $cid=shift @reqdata;
         my $rsapk=shift @reqdata;

         #Some code that needs to check whether there is already a request processed
         #from the server RDBMS table needs to go here, in case we need to abort
         #the client registration (if it already exists).
         my @authinfo=getdbauth();
         my ($dbusername,$dbname,$dbpass,$hostname);

         foreach my $dbentry (@authinfo) {
                ($dbusername,$dbname,$dbpass,$hostname)=split("," , $dbentry);
         }
         
         my $datasource="DBI:mysql:$dbname:$hostname:3306";
		 my $lhltservh=DBI->connect ($datasource, $dbusername, $dbpass, {RaiseError => 1, PrintError => 1});
		 my $SQLh=$lhltservh->prepare("SELECT COUNT(*) FROM lhltable WHERE uuid='$uuid' ");
		 $SQLh->execute();
		 my @cidhits=$SQLh->fetchrow_array();
		 
		 #Does the record exist?
		 if ($cidhits[0]=="1") {
			#Record exists.
			#Make a response file with an error code to send to the client
			open(RESP, ">", "$reghome/response$cid.reg") || die "lusreg Error: Cannot create the response file to register client $uuid: $! \n";
			select RESP;
			print "Status:DENIED#Client exists. Contact LUARM v2 server admin#0302";
			close(RESP);
			
			#Clean up the request and response files. The LUARM client will have to send a new one, after the old DB record is dropped.
			unlink "$reghome/request$cid.luarm" or warn "lusreg Warning: Could not remove request file request$cid.luarm after non effective registration for client $uuid: $! \n";
			
			die "lusreg Error: Client with uuid:$uuid is ALREADY registered in the LHLT database! I cannot register this client, sorry. \n You will need to drop the database record first. \n"; 
			#$SQLh->finish();
		} elsif ( $cidhits[0]=="0") {
			#The record does not exist. We need make an account and SQL INSERT the data.
			#Make a random-ish user id that will upload the data for that client
			my $construid=md5_hex($cid);
			system "useradd -d $userhome/$construid $construid";
			#Generate a secure password for that user id, although an RSA key will be used
			#for client SSH aunthentication
			my $digest=sha256_hex($cid);
			system "echo $digest | passwd --stdin $construid";
			
			#Enable RSA key authentication for the created userid from the root of the client
			mkdir "$userhome/$construid/.ssh" unless -d "$userhome/$construid/.ssh";
			open (RSA, ">>", "$userhome/$construid/.ssh/authorized_keys") || die "lusreg Error: Cannot update the authorized keys file for user $construid to register client $uuid: $! \n";
			select RSA;
			print "$rsapk";
			close(RSA);
			#Ditto for the registrar account
			mkdir "$reghome/.ssh" unless -d "$reghome/.ssh";
			open (REGRSA, ">>", "$reghome/.ssh/authorized_keys") || die "lusreg Error: Cannot update the authorized keys file for the registrar user to register client $uuid: $! \n";
			select REGRSA;
			print "$rsapk";
			close(REGRSA);

			select STDOUT;
			
			#Make the response file passing info back to the client
			open(RESP, ">", "$reghome/response$cid.reg") || die "lusreg Error: Cannot create the response file to register client $uuid: $! \n";
			select RESP;
			print "Status:GRANTED#$construid#$digest";
			close(RESP);

			#Clean up the request and response files, now we are done with it
			unlink "$reghome/request$cid.luarm" or warn "lusreg Warning: Could not remove request file request$cid.luarm after registering client $uuid: $! \n";
	
			select STDOUT;

			my ($ryear,$rmonth,$rday,$rhour,$rmin,$rsec)=timestamp();
			my $lastip="BOGUS.BOGUS.BOGUS.3";
			my $rows=$lhltservh->do ("INSERT INTO lhltable(uuid,cid,ciduser,lastip,ryear,rmonth,rday,rhour,rmin,rsec)"
				   . "VALUES ('$uuid','$cid','$construid','$lastip',"
			   	   . "'$ryear','$rmonth','$rday','$rhour','$rmin','$rsec')" );
		
			if (($rows==-1) || (!defined($rows))) {
	       		print "lusreg Error: No records were altered. Record was not registered.\n";
       		}	
			
			$SQLh->finish();

			#If this is a new registration, we also need to create a database entry for it
			#The name of the database will be the cid string of the registered client WITHOUT THE DASHES
			#Quick hack, roll in the SQL schema from an external file, assuming that the 
			#MySQL password is in .my.cnf
			#Strip the dashes of the $cid
                        $cid =~ s/-//g;

			#Get the timeref
			open(TMR, "<","/proc/uptime");
			my @timerefa=<TMR>;
			close(TMR);
			my @timerefstr=split " ", $timerefa[0];
                  	my $timeref=$timerefstr[0];
			$timeref=~ tr/'.'//d;
			open (DBC, ">", "/dev/shm/$timeref.dbcreate");
			select DBC;
			print "CREATE DATABASE $cid;";
			close(DBC);
			select STDOUT;
			print "cid is $cid \n";
			system ("mysql < /dev/shm/$timeref.dbcreate --password=$dbpass");
			system ("mysql $cid < itpslschema.sql --password=$dbpass");
			unlink "/dev/shm/$timeref.dbcreate";
			

		} #end of elsif

    
}

#Subroutines here
sub getdbauth {
	#DBAUTH path hardwired only on the server side
	unless(open DBAUTH, "./.adb.dat") {
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

