#!/usr/bin/perl -w

# parseproc.pl: A LUARM v2 server script that parses the process entries
# and populates the psinfo RDBMS table of the ITPSLschema
# By George Magklaras@steelcyber scientific

use strict;
#use warnings;
use Data::Dumper;
use Digest::SHA qw(sha1 sha1_hex sha256_hex);
use Digest::MD5 qw(md5 md5_hex md5_base64);
use DBI;
use Time::HiRes qw(usleep clock_gettime gettimeofday clock_getres CLOCK_REALTIME ITIMER_REAL ITIMER_VIRTUAL ITIMER_PROF ITIMER_REALPROF);
use Parallel::ForkManager;
 
#Get the number of server cores to make to parallelize the whole thing a bit
my $corecount=`cat /proc/cpuinfo | grep ^processor | wc -l`;
chomp $corecount;

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
my @cidhits;
my @row;
while (@row=$SQLh->fetchrow_array) {
	push @cidhits, @row;
}
$SQLh->finish();

#Not all hosts/users will need processing. Only the ones that have proc and net files 
#uploaded in the home dirs
my @activeusers;
foreach my $user (@cidhits) {
    	
    	opendir(DIR, "/home/$user") || die "parseproc Error: can't open user directory /home/$user: $!";
		my @myprocfiles = sort grep { /^[1-9][0-9]*.proc/  } readdir(DIR);
		if ($#myprocfiles >= 1) { 
			push(@activeusers, $user);
		}		
} #End of foreach my $user (@cidhits)

#Number of jobs
my $nusers=$#activeusers+1;

#Debug 
print "Running on $corecount server cores and having $nusers active users.\n Users are: @activeusers \n";

my $pm = Parallel::ForkManager->new($corecount);
 
DATA_LOOP:
foreach my $data (@activeusers) {
  # Forks and returns the pid for the child:
  my $pid = $pm->start and next DATA_LOOP;
  procuser("$data");
 
  $pm->finish; # Terminates the child process
}
	

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

sub procuser {
	#Debug
	my $user= shift;
	print "Processing user $user \n";
	opendir(DIR, "/home/$user") || die "parseproc Error: can't open user directory /home/$user: $!";
	my @myprocfiles = sort grep { /^[1-9][0-9]*.proc/  } readdir(DIR);
	#my @sorted_numbers = sort @myprocfiles;
	#Debug
	print "myprocfiles array is: @myprocfiles \n";
	  
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
	
	#Start the process parsing
	foreach my $fitopr (@myprocfiles) {
		open(FHL, "<", "/home/$user/$fitopr");
		my @lines=<FHL>;
		my ($sprocpid,$pid,$ppid,$puid,$procname,$procarg,$procfiles);
		foreach my $line (@lines) {
			#Strip the \n at the end of the line
			chomp $line;
			($sprocpid,$pid,$ppid,$puid,$procname,$procarg,$procfiles)=split("###", $line);
			#Are we dealing with the PID of the scanproc.pl script itself?
			#If yes, we do not need to record that.
			if ($pid==$sprocpid) {
				#Do nothing
			} else {
				my $digeststr1=$pid.$ppid.$puid.$procname.$procarg;
				my $shanorm=sha1_hex($digeststr1);
				#Does this record exist in the database already?
				my $SQLh=$hostservh->prepare("SELECT COUNT(*) FROM psinfo WHERE shanorm='$shanorm' ");
				$SQLh->execute();
				my @shahits=$SQLh->fetchrow_array();
				if ($shahits[0]=="1") {
					#Record exists.
					#Have any of the open files changed?
					my $digeststr2=$pid.$ppid.$puid.$procname.$procarg.$procfiles;
					my $shafull=sha1_hex($digeststr2);
					#Is the $shafull different than the one previously
					#stored in the RDBMS?
					my $SQLh=$hostservh->prepare("SELECT shafull FROM psinfo WHERE shanorm='$shanorm' ");
					$SQLh->execute();
					my @prevshafullhits=$SQLh->fetchrow_array();
					#Debug
					#print "The previous Shafullhit is $prevshafullhits[0] and the new shafull is $shafull \n"; 
					if ( $prevshafullhits[0] eq $shafull ) {
						#Nothing to do
						#Debug
						#print "Nothing to do with the procfiles \n";
					} else { 
						#We need to update the file lists associated with the process
						#Debug
						#print "We need to change the ";
						#print "procfiles: $procfiles \n";
						my @procfilehits=split(" ", $procfiles);
						#Debug
						#print "Pid: $pid sizeofprocfilehits: $#procfilehits \n";
						foreach my $pf (@procfilehits) {
							my $shapf=sha1_hex($pf);
							my $SQLh=$hostservh->prepare("SELECT COUNT(*) FROM fileinfo WHERE shasum='$shapf' AND pid='$pid' AND ppid='$ppid' AND uid='$puid' ");
							$SQLh->execute();
							my @pfilehits=$SQLh->fetchrow_array();
							if ($pfilehits[0]=="1") {
								#File exists do nothing
								#Debug 
								#print "This is an old file from the new file list \n";
							
							} elsif ( $pfilehits[0]=="0" ) {
								#Insert the new file record
								#Are we having a LUARMv2NOOPENFILES flag?
								#(see scanproc.pl)
								if (($pf eq "LUARMv2NOOPENFILES") || ($pf =~ /'/)) {
									#Do nothing
								} else {
									#Insert the file record
									my ($cyear,$cmonth,$cday,$chour,$cmin,$csec)=timestamp();
									$pf=$hostservh->quote($pf);
									my $rows=$hostservh->do ("INSERT INTO fileinfo(shasum,filename,uid,command,pid,ppid,cyear,cmonth,cday,chour,cmin,csec)"
									. "VALUES ('$shapf',$pf,'$puid','$procname','$pid','$ppid',"
									. "'$cyear','$cmonth','$cday','$chour','$cmin','$csec')" );
							
									#Debug
									#print "Inserted new file $pf from existing process $procname with pid $pid \n";
							 
								} #end of if ($pf eq "LUARMv2NOOPENFILES")
							 
							} # end of if ($pfilehits[0]=="1") 
						
						
						} #end of foreach my $pf (@procfilehits)
					} #end of if ($prevshafullhits[0]...)
					
					
					#$SQLh->finish();
				} elsif ( $shahits[0]=="0") {
			#The record does not exist. We need to SQL INSERT it.
			my ($cyear,$cmonth,$cday,$chour,$cmin,$csec)=timestamp();
			my $digeststr2=$pid.$ppid.$puid.$procname.$procarg.$procfiles;
			my $shafull=sha1_hex($digeststr2);
			#Quote the $procfiles and $procarg to ensure that any 
			#special characters of file names will not break the SQL INSERT
			$procarg=$hostservh->quote($procarg);
			$procfiles=$hostservh->quote($procfiles);
			my $rows=$hostservh->do ("INSERT INTO psinfo(shanorm,shafull,uid,pid,ppid,command,arguments,cyear,cmonth,cday,chour,cmin,csec)"
				   . "VALUES ('$shanorm','$shafull','$puid','$pid','$ppid','$procname',$procarg,"
			   	   . "'$cyear','$cmonth','$cday','$chour','$cmin','$csec')" );
			if (($rows==-1) || (!defined($rows))) {
	       		print "parseproc.pl Fatal Error: No process record was altered. Record $line was not registered.\n";
       		}	
       		#For every file entry, we need to make an entry in the
       		#fileinfo table, ONLY IF there are open files recorded
       		my $sofprocfiles=length($procfiles);
       		if ( $sofprocfiles >= 3) {
				my @pfarray=split(" ",$procfiles);
				foreach my $pfile (@pfarray) {
					my $filesha=sha1_hex($pfile);
					$pfile=$hostservh->quote($pfile);
					#print "SHA is $filesha for file $pfile fron uid:$puid of command $procname \n";
					my $rows=$hostservh->do ("INSERT INTO fileinfo(shasum,filename,uid,command,pid,ppid,cyear,cmonth,cday,chour,cmin,csec)"
					. "VALUES ('$filesha',$pfile,'$puid','$procname','$pid','$ppid',"
					. "'$cyear','$cmonth','$cday','$chour','$cmin','$csec')" );
					
				} #end of foreach my $pfile (@pfarray)
			} #ene of if ($sofprocfiles >= 3)  
    
		    
		} #end of elsif ($shahits[0]=="0"
		
			#Debug
			#print "Shanorm is $shanorm \n";
			#print "Pids: $pid and PPids: $ppid and procfiles: $procfiles \n";
		} #end of foreach my $line (@lines)	
	} #end of if ($pid==$procpid)	
		#Here if all goes well, we should be able to remove the
		#client .proc file, as they data exists now on the RDBMS
		unlink "/home/$user/$fitopr" or warn "parseproc.pl Warning: Could not unlink /home/$user/$fitopr: $!";
	
	} #end of my $fitopr (@myprocfiles)
} #end of sub procuser
