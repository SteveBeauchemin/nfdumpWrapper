#!/usr/bin/perl -w
## NFDump-wrapper.pl
##
## Script to intercede between applications and nfdump.
## The intent is to make use of GNU parallel software and have nfdump use more than one CPU
## This is written specifically for Nagios Network Analyzer but should 
## be easy enough to make changes and support any nfdump activity.
## Created by Steve Beauchemin - sbeauchemin@gmail.com - 2017-06-28
##

use strict; 
use warnings; 
use Getopt::Long qw(:config no_ignore_case);
use Date::Format;
use Time::Local;
use File::Basename;
use File::chdir;
use File::Path;
use File::Remove 'remove';
use Data::Dump 'dump';
use Cwd 'abs_path';

## Absolute on off
# Define an on/true off/false switch for the Entire wrapper.
# This is handy if you simply want to log the syntax that any application is sending to nfdump.
# false means to never run GNU parallel code and just pass the nfdump command syntax with no changes.
# true means make use of GNU parallel.
#my $MasterPass = "false";
my $MasterPass = "true";

## There is log data keps for each run so the syntax can be examined. So see VERBOSE log data change the following
# variable to true
#my $Verbose = "true";
my $Verbose;

# Set a default multiplier for time intervals
# setting a default of 1 hour - if you change this, test the output using debug to make sure you like the result
my $interval = "1";

# define location variables
# Install the wrapper here
my $BASEDIR = "/usr/local/nfdumpWrapper/";
# Put temporary files here - They should get cleaned out on a regular basis
# automatically by the program. Maybe sneak in a time stamp check in the cleanup just in case.
#my $QUEDIR = "/var/tmp/parallelqueue/";
#my $QUEDIR = "/tmp/parallelqueue/";
my $QUEDIR = "/tmp/";
#my $TMPDIR = "/var/tmp/nfdumptemp/";
#my $TMPDIR = "/tmp/nfdumptemp/";
my $TMPDIR = "/tmp/";

# Make sure that this is the actual nfdump binary as the
# real nfdump is renamed to .nfdump
my $command = "/usr/local/bin/.nfdump";

# ================================================================= No USER modifiable parameters below here
# I hope
my $LOG;
my $NFDLOCATION = "";
my $DEBUG;
my $quefile = "";
my $counter = "1";

#
## Conditional on off
# Some commands should not be run as a parallel process.
# Define here whether we are simply passing through the command,
# or are we using GNU parallel to make nfdump more efficient.
# A value of false is the necessary default and will be changed
# automatically as needed if a parameter in use will benefit.
my $passthru = "false"; # using parallel processing

## Some parameters allow for nfdump to create intermediate files. This makes using parallel much easier.
# If the -a -A -b or -B are used, then we can use -w [outfile]. What this means is that we can use parallel and
# output to a special directory all the small parallel file results. Then, against that location we can run the actual
# syntax we were requesing in the first place, and it will run in less than a second, as the data has been processed and
# reduced to what we actually care about. If a parameter would be a candidate then this vaulue is changed automatically.
# The default is false.
my $useoutfile = "false";

## If looking for Top Talkers then we need to do a different parallel syntax. 
# We need to capture the return data in an array and processes it.
# So we need to be aware that we want a Top Talker list by using some variable
# The default for this is false until we use the -n parameter
my $toptalker = "false";

# filter would be the last command line item using no parameter, just a value
my $filter = "";

# Make arrays to hold data
my @DirList;
my @TimeList;

# Detect how the wrapper is invoked
# basename of nfdump means we are being used by a 3rd part app
if (basename($0) =~ m/nfdump/) {
  #$LOG = $BASEDIR . "log/nfdump.log";
  $LOG = $BASEDIR . "log/nfdump.log";
  # 3rd party app would be confused if we output extra information so turn off DEBUG
  $DEBUG=0;
} else {
  # running the perl script by its real name - probably manually for debug
  $LOG = $BASEDIR . "logtest/testing-nfdump.log";
  $DEBUG=0;  # change this one for debugging 
  print "\nDebug is set to $DEBUG\n\n" if $DEBUG;
}

# ====================================== Get command line options
# ===============================================================

# The list of ARGS below should represent every possible ARG that nfdump understands
# The list is acquired from man nfdump
GetOptions(
        "r=s"	=> \my $opt_r,
        "R=s"	=> \my $opt_R,
        "M=s"	=> \my $opt_M,
        "O=s"	=> \my $opt_O,
        "w=s"	=> \my $opt_w,
        "f=s"	=> \my $opt_f,
        "t=s"	=> \my $opt_t,
        "c=i"	=> \my $opt_c,
        "a"	=> \my $opt_a,
        "A=s"	=> \my $opt_A,
        "b"	=> \my $opt_b,
        "B"	=> \my $opt_B,
        "I"	=> \my $opt_I,
        "D=s"	=> \my $opt_D,
        "s=s"	=> \my $opt_s,
        "l=s"	=> \my $opt_l,
        "L=s"	=> \my $opt_L,
        "n=i"	=> \my $opt_n,
        "o=s"	=> \my $opt_o,
        "q"	=> \my $opt_q,
        "N"	=> \my $opt_N,
        "i=s"	=> \my $opt_i,
        "v=s"	=> \my $opt_v,
        "E=s"	=> \my $opt_E,
        "x=s"	=> \my $opt_x,
        "j"	=> \my $opt_j,
        "z"	=> \my $opt_z,
        "J=i"	=> \my $opt_J,
        "Z"	=> \my $opt_Z,
        "X"	=> \my $opt_X,
        "V"	=> \my $opt_V,
        "h"	=> \my $opt_h,
);

# if any command line data is left over save it to filter
if ($ARGV[0]) {
  foreach (@ARGV) {
    $filter .= " $_";
  }
}


# =============================== Process command line parameters
# ============================= and start to construct the syntax
# ===============================================================

if ($opt_r) {
  # constructing the nfdump command line -r
  print " -r \'$opt_r\'" if $DEBUG;
  $command .= " -r \'$opt_r\'";
}

if ($opt_R) {
  # constructing the nfdump command line -R
  print " -R \'$opt_R\'" if $DEBUG;
  #$command .= " -R \'$opt_R\'";
  # Use parallel processing - do not simply pass through to nfdump
  $passthru = "false";
}

if ($opt_M) {
  # constructing the nfdump command line -M
  print " -M \'$opt_M\'" if $DEBUG;
  #$command .= " -M \'$opt_M\'";
  # Use parallel processing - do not simply pass through to nfdump
  $passthru = "false";
}

if ($opt_O) {
  # constructing the nfdump command line -O
  print " -O \'$opt_O\'" if $DEBUG;
  $command .= " -O \'$opt_O\'";
}

if ($opt_w) {
  # constructing the nfdump command line -w
  print " -w \'$opt_w\'" if $DEBUG;
  $command .= " -w \'$opt_w\'";
  # if the -w is passed as a parameter then something unusual is being requested so
  # lets become invisible and just run the nfdump syntax we are sent. 
  # Entering Master Pass Thru mode...
  $MasterPass = "false";
}

if ($opt_f) {
  # constructing the nfdump command line -f
  print " -f \'$opt_f\'" if $DEBUG;
  $command .= " -f \'$opt_f\'";
}

if ($opt_t) {
  # constructing the nfdump command line -t
  print " -t \'$opt_t\'" if $DEBUG;
  #$command .= " -t \'$opt_t\'";
  # Use parallel processing - do not simply pass through to nfdump
  $passthru = "false";
}

if ($opt_c) {
  # Introduce a small delay here to prevent multiple NNA queries from running in the same dir space
  # This happens when using the tab Nagios XI and it makes 2 requests to NNA at the same exact second
  sleep(2);
  # constructing the nfdump command line -c
  print " -c \'$opt_c\'" if $DEBUG;
  $command .= " -c \'$opt_c\'";
}

if ($opt_a) {
  # constructing the nfdump command line -a
  print " -a" if $DEBUG;
  $command .= " -a";
  # This parameter implies that we can use Parallel and an Intermediate directory
  $passthru = "false";
  $useoutfile = "true";
}

if ($opt_A) {
  # constructing the nfdump command line -A
  print " -A \'$opt_A\'" if $DEBUG;
  $command .= " -A \'$opt_A\'";
  # This parameter implies that we can use Parallel and an Intermediate directory
  $passthru = "false";
  $useoutfile = "true";
  # In the GUI if you run a Report - and then click on a hyperlink to see by port
  # the system runs a Query that generates many pages but fails until I fix the Top Talker
  # and then this will be similar.
  #my ($tst1,$tst2)=split(",",$opt_A);
  #if (($tst1 eq "srcport") && ($tst2 eq "dstport")) {
  #  $MasterPass = "false";
  #}
  #if (($tst1 eq "srcip") && ($tst2 eq "srcport")) {
  #  $MasterPass = "false";
  #}
  #if (($tst1 eq "srcip") && ($tst2 eq "dstip")) {
  #  $MasterPass = "false";
  #}
  #if (($tst1 eq "dstip") && ($tst2 eq "srcip")) {
  #  $MasterPass = "false";
  #}
}

if ($opt_b) {
  # constructing the nfdump command line -b
  print " -b" if $DEBUG;
  $command .= " -b";
  # This parameter implies that we can use Parallel and an Intermediate directory
  $passthru = "false";
  $useoutfile = "true";
}

if ($opt_B) {
  # constructing the nfdump command line -B
  print " -B" if $DEBUG;
  $command .= " -B";
  # This parameter implies that we can use Parallel and an Intermediate directory
  $passthru = "false";
  $useoutfile = "true";
}

if ($opt_I) {
  # constructing the nfdump command line -I
  print " -I" if $DEBUG;
  $command .= " -I";
}

if ($opt_D) {
  # constructing the nfdump command line -D
  print " -D \'$opt_D\'" if $DEBUG;
  $command .= " -D \'$opt_D\'";
}

if ($opt_s) {
  # constructing the nfdump command line -s
  print " -s \'$opt_s\'" if $DEBUG;
  $command .= " -s \'$opt_s\'";
}

if ($opt_l) {
  # constructing the nfdump command line -l
  print " -l \'$opt_l\'" if $DEBUG;
  $command .= " -l \'$opt_l\'";
}

if ($opt_L) {
  # constructing the nfdump command line -L
  print " -L \'$opt_L\'" if $DEBUG;
  $command .= " -L \'$opt_L\'";
}

if ($opt_n) {
  # constructing the nfdump command line -n
  print " -n \'$opt_n\'" if $DEBUG;
  $command .= " -n \'$opt_n\'";
  # The query is for Top Talker data, so if we run parallel we need to merge the data, 
  # sort it, add it, whatever it takes to format it as if it were a single query.
  $toptalker = "true";
}

if ($opt_o) {
  # constructing the nfdump command line -o
  print " -o \'$opt_o\'" if $DEBUG;
  $command .= " -o \'$opt_o\'";
}

if ($opt_q) {
  # constructing the nfdump command line -q
  print " -q" if $DEBUG;
  $command .= " -q";
}

if ($opt_N) {
  # constructing the nfdump command line -N
  print " -N" if $DEBUG;
  $command .= " -N";
}

if ($opt_i) {
  # constructing the nfdump command line -i
  print " -i \'$opt_i\'" if $DEBUG;
  $command .= " -i \'$opt_i\'";
}

if ($opt_v) {
  # constructing the nfdump command line -v
  print " -v \'$opt_v\'" if $DEBUG;
  $command .= " -v \'$opt_v\'";
}

if ($opt_E) {
  # constructing the nfdump command line -E
  print " -E \'$opt_E\'" if $DEBUG;
  $command .= " -E \'$opt_E\'";
}

if ($opt_x) {
  # constructing the nfdump command line -x
  print " -x \'$opt_x\'" if $DEBUG;
  $command .= " -x \'$opt_x\'";
}

if ($opt_j) {
  # constructing the nfdump command line -j
  print " -j" if $DEBUG;
  $command .= " -j";
}

if ($opt_z) {
  # constructing the nfdump command line -z
  print " -z" if $DEBUG;
  $command .= " -z";
}

if ($opt_J) {
  # constructing the nfdump command line -J
  print " -J \'$opt_J\'" if $DEBUG;
  $command .= " -J \'$opt_J\'";
}

if ($opt_Z) {
  # constructing the nfdump command line -Z
  print " -Z" if $DEBUG;
  $command .= " -Z";
  # Do not use using parallel processing as this is just a syntax verification
  $MasterPass = "false";
}

if ($opt_X) {
  # constructing the nfdump command line -X
  print " -X" if $DEBUG;
  $command .= " -X";
}

if ($opt_V) {
  # constructing the nfdump command line -V
  print " -V" if $DEBUG;
  $command .= " -V";
}

if ($opt_h) {
  # constructing the nfdump command line -h
  print " -h" if $DEBUG;
  $command .= " -h";
}

if ($filter) {
  # constructing the nfdump command line tail-end filter
  print " \'$filter\'\n\n" if $DEBUG;
  # The filter has to always appear last on the command line so do not add it here.
  #$command .= " \'$filter\'";
}

print "\n\n" if $DEBUG;

# ===============================================================
# --------------------------------------------------- LOG section
# ===============================================================

# Save the initial command to a log file so we can examine syntax later
my $logcmd = $command;
if ($opt_R) {
  $logcmd .= " -R \'$opt_R\'";
}
if ($opt_M) {
  $logcmd .= " -M \'$opt_M\'";
}
if ($opt_t) {
  $logcmd .= " -t \'$opt_t\'";
}
if ($filter) {
  $logcmd .= " \'$filter\'";
}
my $eventtime = time2str("%Y-%m-%d %I:%M %p %Z", time);

# Write the nfdump syntax in an untouched state.
open(my $OUTPUT, '>>', $LOG);
print $OUTPUT "---------------------------------------------------------" .  $eventtime . " \n" ;
print $OUTPUT "Initial syntax untouched is\n" if $Verbose;
print $OUTPUT "$logcmd\n\n" if $Verbose;

# ===============================================================
#  ------------------------------------------------- Main Section
# ===============================================================
# Do we or Don't we run GNU Parallel - test the circumstances

# set a time that all parts of this run will use
my $tstamp = time;

if ($MasterPass eq "false") {
  # IF false, then skip all  further efforts as we are not enabled.
  # So just run the nfdump command as submitted with no performance improvements
  # Use the logcmd from above as this represents unmodified input
  system($logcmd) unless $DEBUG;
  print "MasterPass false mode in effect - We would have run - $logcmd\n" if $DEBUG;
  print $OUTPUT "MasterPass false mode in effect - We would have run - $logcmd\n\n";
  close $OUTPUT;
} else {
  # We are globally enabled and will enhance performance based on the parameters submitted to nfdump
  if ($passthru eq "true") {
    # The parameters passed provide no enhancement possibility so execute nfdump and hide in plain sight
    system($logcmd) unless $DEBUG;
    print "No Parallel needed - We would have run\n$logcmd\n\n" if $DEBUG;
    print $OUTPUT "No Parallel needed - We would have run\n$logcmd\n\n";
  } else {
    print "Parallel may be needed - processing parameters for\n$logcmd\n\n" if $DEBUG;
    print $OUTPUT "Parallel may be needed - processing parameters for\n$logcmd\n\n";
    # Process the directories from -M
    # populate array with directory list
    @DirList = &DirToArray();
    my $dircount = @DirList;
    print "This is the expanded directory list \n" if $DEBUG;
    dump @DirList if $DEBUG;
    print "\n" if $DEBUG;
    print $OUTPUT "This is the expanded directory list - broken up to $dircount items\n" if $Verbose;
    print $OUTPUT @DirList if $Verbose;
    print $OUTPUT "\n\n" if $Verbose;
    #
    # Process time range for -t
    # populate array with time ranges
    @TimeList = &TimeToArray();
    my $timecount = @TimeList;
    print "This is the expanded time range list \n" if $DEBUG;
    dump @TimeList if $DEBUG;
    print "\n" if $DEBUG;
    print $OUTPUT "This is the expanded time range list - broken up to $timecount items\n" if $Verbose;
    print $OUTPUT @TimeList if $Verbose;
    print $OUTPUT "\n\n" if $Verbose;

    #
    if (($dircount eq "1") && ($timecount eq "1") || ($toptalker eq "true")) {
      # each is one item long so just run the nfdump command
      system($logcmd) unless $DEBUG;
      print "No Parallel needed - one dir and one timelist - Or Top Talker is asked for\n" if $DEBUG;
      print "We would have run\n$logcmd\n\n" if $DEBUG;
      print $OUTPUT "No Parallel needed - one dir and one timelist - Or Top Talker is asked for\n";
      print $OUTPUT "We would have run\n$logcmd\n\n" if $Verbose;
    } else {
      # continue with the GNU parallel tasks
      #
      # Include any Pre Process commands or parameters
      # Such as making a directory
      print $OUTPUT "Will now run the sub PreProcess\n\n" if $Verbose;
      &PreProcess();
      #
      # write the parallel queue file using the arrays from above and any extended command syntax
      print $OUTPUT "Will now run the sub MakeQueueFile\n\n" if $Verbose;
      $quefile = &MakeQueueFile();
      #&MakeQueueFile();
      print "queue File $quefile\n" if $DEBUG;
      print $OUTPUT "queue File $quefile\n\n" if $Verbose;
      # display the queue file so we can tell what would have run
      &printfile($quefile) if $DEBUG;
      #
      # Do the work by using the queue file
      # run parallel with proper parameters to be nice
      print $OUTPUT "Will now run the sub runparallel with $quefile\n\n" if $Verbose;
      &runparallel($quefile);
      #
      # Finish up the display of data
      print $OUTPUT "Will now run the sub runFinalPass\n\n" if $Verbose;
      &runFinalPass();
      #
      # Clean up any temporary files
      # Only after all items work should this be allowed
      print $OUTPUT "Will now run the sub RunCleanup for now\n\n" if $Verbose;
      #print $OUTPUT "NOT gonna run the sub RunCleanup for now\n\n";
      # Add a slight delay and allow files to finish any activity that may still be running
      sleep(4);
      &RunCleanup();
      #
    }
  }
}
close $OUTPUT;
# from here down are subroutines - we should never see the following exit line
exit;

# -----------------------------------------------------------------
# Define Subroutines
# -----------------------------------------------------------------

# -----------------------------------------------------------------
sub DirToArray() {
  # take the -M parameter $opt_M and return an array
  my @dirlist = split(":", $opt_M);
  my @results;
  #
  # Process the list and dear with relative path versus absolute path
  #  remember the first dir as that is the fully qualified one
  #my $base = $dirlist[0];
  my $base = shift @dirlist;
  push (@results, $base);
  #print "\n base dir is $base \n" if $DEBUG;
  #
  # Loop through the rest of the array and convert relative to absolute
  foreach my $dir (@dirlist) {
    my $path = $base . $dir;
    my $newpath = abs_path($path) . "/";
    push (@results, $newpath);
  }
  #
  print $OUTPUT "Completed the directory expansion\n\n" if $Verbose;
  return @results;
}

# -----------------------------------------------------------------
sub TimeToArray() {
  my @results;
  # Only slice up the time when it will be useful - add to this if you know something I don't
  if ($useoutfile eq "true") {
    my $onehour = "3600"; # in seconds
    #my $fifteen = "900"; # in seconds
    my $fifteen = "600"; # set to 10 minutes in seconds - try just a little smaller... see what happens - testing...
    # Set number to increment by
    my $skip = $interval * $onehour;
  
    # -t '2017/06/27.11:42:51-2017/06/27.15:42:50'
    # take the -t parameter $opt_t and return an array
    my ($start,$end) = split("-", $opt_t);
    #print "Start is $start and End is $end\n" if $DEBUG;

    # Separate the elements
    my ($syear,$smonth,$sday,$shour,$sminute,$ssecond) = split /[\/\.:]/, $start;
    my ($eyear,$emonth,$eday,$ehour,$eminute,$esecond) = split /[\/\.:]/, $end;

    #print "Starting $syear,$smonth,$sday,$shour,$sminute,$ssecond Ending $eyear,$emonth,$eday,$ehour,$eminute,$esecond \n" if $DEBUG;
    # Convert to Epoch
    my $initialstart = timelocal($ssecond,$sminute,$shour,$sday,$smonth,$syear);
    my $initialend = timelocal($esecond,$eminute,$ehour,$eday,$emonth,$eyear);
    #print "Starting Epoch Time is $initialstart Ending Epoch Time is  $initialend \n" if $DEBUG;
  
    # Retain initialstart and initialend by using temporary names
    my $workingstart = $initialstart;
    my $workingend = $initialstart + $skip;
    #print "Working Start Epoch Time is $workingstart Working End Epoch Time is $workingend \n" if $DEBUG;
    # Start loop to step through time intervals
    do {
      # Convert Epoch to -t format
      my $displaystart = &EpochToT($workingstart);
      my $displayend = &EpochToT($workingend);
      #print "\nDisplay Start $displaystart Display End $displayend \n" if $DEBUG;
      # Do not exceed the original end time - first time through the loop
      if ($workingend > $initialend) {
        push (@results, $displaystart . "-" . $end);
      } elsif ($workingend + $skip + $fifteen < $initialend) {
        push (@results, $displaystart . "-" . $displayend);
      } else {
        push (@results, $displaystart . "-" . $end);
      }
      $workingstart = $workingend + 1;
      $workingend += $skip;
    } while ($initialend > $workingend);
  } else {
    # do not modify time
    push (@results, $opt_t);
  }
  print $OUTPUT "Completed the time range expansion\n\n" if $Verbose;
  return @results;
}

#-------------------------------------------------------------------------
sub EpochToT($) {
  my $toconvert = shift;
  my ($sec,$min,$hour,$day,$month,$year) = localtime($toconvert);
  # correct the date and month for humans
  $year = 1900 + $year;
  #$month++;
  # Format for nfdump
  my $date = sprintf "%04d/%02d/%02d.%02d:%02d:%02d", $year, $month, $day, $hour, $min, $sec;
  return $date;
}

#-------------------------------------------------------------------------
sub PreProcess() {
  if ($useoutfile eq "true") {
    $NFDLOCATION = $TMPDIR;
    print $OUTPUT "Using $TMPDIR as an  Intermediate directory $NFDLOCATION\n\n" if $Verbose;

    print "Intermediate directory is $NFDLOCATION\n" if $DEBUG;
    if (! -e $NFDLOCATION) {
      print $OUTPUT "Intermediate directory $NFDLOCATION is NOT available\n\n" if $Verbose;
    } else {
      print $OUTPUT "Intermediate directory $NFDLOCATION is available\n\n" if $Verbose;
    }
  }
  # Add any other pre process syntax or necessary steps here before the queue file is created
  print $OUTPUT "End of PreProcess\n\n" if $Verbose;
}

#-------------------------------------------------------------------------
sub MakeQueueFile() {
  my $extendparam = "";
  # open the parallel queue file for write
  my $queuefile = $QUEDIR . "queue." . $tstamp;
  print $OUTPUT "Queue File counter starts at $counter data will be written to $queuefile\n\n";
  open(my $mfh, '>', "$queuefile") or print $OUTPUT "Oops, we cannot open the queue file here - $queuefile $!\n";
  print $OUTPUT "Queue File open for writing $queuefile\n\n";
  # iterate the arrays and write to the queue file
  foreach my $dir (@DirList) {
    foreach my $increment (@TimeList) {
      # if we can use an intermediate directory - then make up incremental file names
      if ($useoutfile eq "true") {
        my $filecounter = sprintf("%04d", $counter);
        $extendparam = " -w \'" . $NFDLOCATION . "nfdfile." . $tstamp . "-" . $filecounter . "\'";
        $counter++;
      }
      if ($filter) {
        print $mfh "$command $extendparam -R \'$opt_R\' -M \'$dir\' -t \'$increment\' \'$filter\'\n";
        print $OUTPUT "$command $extendparam -R \'$opt_R\' -M \'$dir\' -t \'$increment\' \'$filter\'\n\n" if $Verbose;
      } else {
        print $mfh "$command $extendparam -R \'$opt_R\' -M \'$dir\' -t \'$increment\'\n";
        print $OUTPUT "$command $extendparam -R \'$opt_R\' -M \'$dir\' -t \'$increment\'\n\n" if $Verbose;
      }
    }
  }
  close $mfh;
  print $OUTPUT "closed the file $queuefile\n\n" if $Verbose;
  # return the queue file name
  return "$queuefile";
}

#-------------------------------------------------------------------------
sub printfile($) {
  my $filename = shift;
  open(my $pfh, '<', $filename)
    or print $OUTPUT "Could not open the parallel queue file '$filename' $!";
  while (my $row = <$pfh>) {
    chomp $row;
    print "$row\n";
  }
  close $pfh;
}

#-------------------------------------------------------------------------
sub runparallel($) {
  # This sub will prepare files for the Final Pass. It should have no STDOUT
  # queue file name
  my $que = shift;
  print "Parallel is Processing Queue File $que\n" if $DEBUG;
  print $OUTPUT "Parallel is Processing Queue File $que\n\n";
  #exec(cat $que | parallel -j +0) unless $DEBUG;
  # the output needs to be hidden from display here so capture it to a variable
  #my $parallelout = `cat $que | parallel -j +0`;
  my $parallelout = qx(cat $que | parallel -j +0 2>&1);
  print $OUTPUT "Parallel qx (cat $que | parallel -j +0) has run\n\n";
}

#-------------------------------------------------------------------------
sub runFinalPass() {
  # if we used the intermediate directory, then all our stuff is cached there waiting to display for NNA
  # we just need to run nfdump a special way. so lets do that by getting the command syntax correctly set.
  print $OUTPUT "Starting a Final Pass\n\n" if $Verbose;
  if ($useoutfile eq "true") {
    my $startcount = "0001";
    my $endcount = sprintf("%04d", $counter);
    my $range = $NFDLOCATION . "nfdfile." . $tstamp . "-" . $startcount . ":nfdfile." . $tstamp . "-" . $endcount;
    if ($filter) {
      $command .= " -R \'$range\' -t \'$opt_t\' \'$filter\'";
    } else {
      $command .= "-R \'$range\' -t \'$opt_t\'";
    }
    # run the command and let the output go to NNA
    print $OUTPUT "Running special nfdump to aggregate Intermediate file data\n";
    print $OUTPUT "Running syntax is\n$command\n\n";
    system($command);
    print "DEBUG is on - parallel may have been run - this final pass is to run\n$command\n\n" if $DEBUG;
    print $OUTPUT "Intermediate file data has been run\n\n" if $Verbose;
  }
}
#-------------------------------------------------------------------------
sub RunCleanup() {
  #return;
  
  {
    my $ctr = "0";
    # Clean up nfdfile.* files in the $TMPDIR
    $CWD = $TMPDIR;
    # to delete all nfdfiles and not the ones we just made
    #my $basefile = "nfdfile.*";
    # to delete just the nfdfiles we just made
    my $basefile = "nfdfile." . $tstamp . "*";
    print $OUTPUT "The file prefix for deletion is " . $basefile  . "\n";
    my @nfdfilelist=<"$basefile">;
    foreach my $del (@nfdfilelist) {
      unlink $del;
      $ctr++;
      print $OUTPUT "Deleted the " . $del  . " file\n" if $Verbose;
    }
    print $OUTPUT "Removed  " . $ctr  . " files\n";
  }

  {
    my $ctr = "0";
    # Clean up queue.* files in the $QUEDIR
    $CWD = $QUEDIR;
    # to delete all queue files and not the ones we just made
    #my $basefile = "queue.*";
    # to delete just the queue file we just made
    my $basefile = "queue." . $tstamp;
    print $OUTPUT "The file prefix for deletion is " . $basefile  . "\n";
    my @queuelist=<"$basefile">;
    foreach my $del (@queuelist) {
      unlink $del;
      $ctr++;
      print $OUTPUT "Deleted the " . $del  . " file\n" if $Verbose;
    }
    print $OUTPUT "Removed  " . $ctr  . " files\n";
  }

}

#-------------------------------------------------------------------------
# end of code
__END__

# These are examples of syntax copied from the log file while in pass thru mode
#
# One =captured= example of nfdump options modified to be on separate lines so we can see each piece
# We are only concerned here with -t or $opt_t
# /usr/local/bin/nfdump \
# -M '/usr/local/nagiosna/var/crmonrah03/flows/' \
# -R . \
# -t '2017/06/22.17:05:17-2017/06/23.17:05:16' \
# -N \
# -n '5' \
# -s 'dstip/bytes' \
# -o 'csv'
# 
#
# Another =captured= example with multiple sources used from multiple file locations
# This is from a Source Group query
# We are only concerned here with -M or $opt_M
# /usr/local/bin/.nfdump \
# -R '.' \
# -M '/usr/local/nagiosna/var/RCNetFlow9908/flows/:../../RCNetFlow9909/flows/:../../RCNetFlow9910/flows/:../../crmonrah03/flows/:../../RCNetFlow9901/flows/:../../RCNetFlow9902/flows/:../../RCNetFlow9903/flows/:../../RCNetFlow9904/flows/:../../RCNetFlow9905/flows/:../../RCNetFlow9906/flows/:../../RCNetFlow9907/flows/' \
# -t '2017/07/05.15:41:42-2017/07/05.17:41:41' \
# -s 'srcip/bytes' \
# -n '5' \
# -o 'csv' \
# -N
#
#
