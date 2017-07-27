#!/usr/bin/perl -w
## NFDump-wrapper.pl
##
## Script to intercede between applications and nfdump.
## The intent is to make use of GNU parallel software and have nfdump use more than one CPU
## This is written specifically for Nagios Network Analyzer but should 
## be easy enough to make changes and support any nfdump activity.
## Created by Steve Beauchemin - sbeauchemin@gmail.com - 2017-06-28
## Version 1.0.1
##

use strict; 
use warnings; 
use Getopt::Long qw(:config no_ignore_case);
use Date::Format;
use Time::Local;
use File::Basename;
use File::chdir;
use File::Path qw(make_path remove_tree);
use File::Remove 'remove';
use Data::Dump 'dump';
use Cwd 'abs_path';

# Make sure that the perl modules listed above are installed
# perl -MCPAN -e shell
# install Getopt::Long
# install Date::Format
# install Time::Local
# install File::Basename
# install File::chdir
# install File::Path
# install File::Remove
# install Data::Dump
# install Cwd
# exit

## Absolute on off
# Define an on/true off/false switch for the Entire wrapper.
# This is handy if you simply want to log the syntax that any application is sending to nfdump.
# false means to never run GNU parallel code and just pass the nfdump command syntax with no changes.
# true means make use of GNU parallel.
#my $MasterPass = "true"; # we need to NOT use the wrapper at this time for various and sundry reasons so turn it completely off
my $MasterPass = "false"; # we will not simply pass through - we are gonna try to use parallel processing

## There is log data kept for each run so the syntax can be examined. 
# To see VERBOSE log data change the following variable to 1
my $Verbose = 0;
#my $Verbose = 1;

# Set a default multiplier for time intervals
# setting a default of 1 hour - if you change this, test the output using debug to make sure you like the result
# Find your preferred setting - these numbers are what I observed at one time
#my $interval = "1"; # chords take about 80 seconds <===  Worst setting... one hour chunks
#my $interval = "2"; # chords take about 45 seconds
#my $interval = "3"; # chords take about 41 seconds
my $interval = "4"; # chords take about 36 seconds
#my $interval = "5"; # chords take about 39 seconds
#my $interval = "12"; # chords take about 42 seconds - no time split - only Dir split

# Make sure that this is aimed at the actual nfdump binary as the
# real nfdump is renamed to .nfdump or otherwise hidden somewhere
# mv /usr/local/bin/nfdump /usr/local/bin/.nfdump
my $command = "/usr/local/bin/.nfdump";

# define location variables
# Install the wrapper here
my $BASEDIR = "/usr/local/nfdumpWrapper/";
# then link it to nfdump
# ln -s /usr/local/nfdumpWrapper/NFDump-wrapper.pl /usr/local/bin/nfdump
# that is an easy install...

my $QUEDIR = "/tmp";
my $TMPDIR = "/tmp";
my $LOGDIR = "/tmp";

# make sure to install GNU Parallel from here => https://www.gnu.org/software/parallel/
# Make sure to deal with the parallel citation
# Run parallel manually and it will tell you what to type to remove the citation text
# Remove the citation as the root user

# ================================================================= No USER modifiable parameters below here
# I hope

my $alltstamp = time;

my $DEBUG;
my $LOG;

# Detect how the wrapper is invoked
# basename of nfdump means we are being used by a 3rd part app
if (basename($0) =~ m/nfdump/) {
  $QUEDIR .= "/nfdqueue/";
  $TMPDIR .= "/nfdtemp/";
  $LOGDIR .= "/nfdlogs/";
  $LOG = $LOGDIR . "nfdump.log";
  # 3rd party app would be confused if we output extra information so turn off DEBUG
  $DEBUG=0;
} else {
  # running the perl script by its real name - probably manually for debug
  $QUEDIR .= "/testnfdqueue/";
  $TMPDIR .= "/testnfdtemp/";
  $LOGDIR .= "/testnfdlogs/";
  $LOG = $LOGDIR . "nfdump.log";
  $DEBUG=0;  # change this one for debugging 
  print "\nDebug is set to $DEBUG\n\n" if $DEBUG;
}

# check for temporary directories - make them if needed
# Note: we will make other directories inside  the nfdtemp location
if ( ! -d $QUEDIR ) {
  make_path($QUEDIR, { mode => 0775 });
}
if ( ! -d $TMPDIR ) {
  make_path($TMPDIR, { mode => 0775 });
}
if ( ! -d $LOGDIR ) {
  make_path($LOGDIR, { mode => 0775 });
}

## Conditional on off
# Some commands should not be run as a parallel process.
# Define here whether we are simply passing through the command,
# or are we using GNU parallel to make nfdump more efficient.
# A value of false is the necessary default and will be changed
# automatically as needed if a parameter in use will benefit.
my $passthru = "false"; # we will not simply pass through - we are gonna be using parallel processing

## If looking for Top Talkers then we need to do a different parallel syntax. 
# We need to capture the return data in an array and processes it.
# So we need to be aware that we want a Top Talker list by using some variable
# The default for this is false until we use the -n parameter
my $toptalker = "false";

# filter would be the last command line item using no parameter, just a value
my $filter = "";

# Make variables and arrays to hold data
my $dircount;
my @DirList;
my $timecount;
my @TimeList;
my @toptalkersparallelout;
my $NFDLOCATION = "";
my $quefile = "";

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

# if any command line data is left over save it to the filter variable
if ($ARGV[0]) {
  foreach (@ARGV) {
    $filter .= "$_";
  }
}


# =============================== Process command line parameters
# ============================= and begin to construct the syntax
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
}

if ($opt_M) {
  # constructing the nfdump command line -M
  print " -M \'$opt_M\'" if $DEBUG;
  #$command .= " -M \'$opt_M\'";
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
}

if ($opt_c) {
  # constructing the nfdump command line -c
  print " -c \'$opt_c\'" if $DEBUG;
  #$command .= " -c \'$opt_c\'";
}

if ($opt_a) {
  # constructing the nfdump command line -a
  print " -a" if $DEBUG;
  $command .= " -a";
}

if ($opt_A) {
  # constructing the nfdump command line -A
  print " -A \'$opt_A\'" if $DEBUG;
  $command .= " -A \'$opt_A\'";
}

if ($opt_b) {
  # constructing the nfdump command line -b
  print " -b" if $DEBUG;
  $command .= " -b";
}

if ($opt_B) {
  # constructing the nfdump command line -B
  print " -B" if $DEBUG;
  $command .= " -B";
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

# ===========================================================================================
# ===========================================================================================
## Make decisions here based on the command line parameters - use proper judgement when selecting order of precedence
#
if ($opt_c) {
  # The use of opt_c implies that this is a Chord Diagram.
  # Introduce a small delay here to prevent multiple NNA queries from running  at the same exact second.
  # This happens when using the tab in Nagios XI and it makes 2 requests to NNA. It also happens on
  # the Summary page. A small delay makes sure that the tstamp is different for each run.
  # Since we use a time stamp in the code for making directories we need to make sure that the times are different
  # and the directory names are different.
  sleep(2);
}
if (($opt_t) || ($opt_M) || ($opt_R)) {
  # These are good candidates for use of parallel processing - do not simply pass through to nfdump
  $passthru = "false";
}
if (($opt_B) || ($opt_b) || ($opt_A) || ($opt_a)) {
  # Use of these parameters implies that we can use Parallel and an Intermediate directory
  $passthru = "false";
}
if ($opt_n) {
  # The query is for Top Talker data.
  $toptalker = "true";
}
if (($opt_Z) || ($opt_w)) {
  # if the -Z is passed then we are just doing a syntax check
  # if the -w is passed as a parameter then something unusual is being requested so
  # in either case lets become invisible and just run the nfdump syntax we are sent.
  # Entering Master Pass Thru mode...
  $MasterPass = "true";
}
# ===========================================================================================

print "\n\n" if $DEBUG;

# ===============================================================
# --------------------------------------------------- LOG section
# ===============================================================

# Save the initial command to a log file so we can examine syntax later
my $logcmd = $command;
if ($opt_c) {
  $logcmd .= " -c \'$opt_c\'";
}
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

my $eventtime = time2str("%Y-%m-%d %I:%M:%S %p %Z", time);

# Write the nfdump syntax in an untouched state.
open(my $OUTPUT, '>>', $LOG);
print $OUTPUT "\n\nNew dump started\n";
print $OUTPUT "========================================================= Start " .  $eventtime . " \n";
print $OUTPUT "Initial syntax untouched is\n" if $Verbose;
print $OUTPUT "$logcmd\n\n" if $Verbose;

# set a time that all parts of this code will use for making items
my $tstamp = time;

# ===============================================================
#  ------------------------------------------------- Main Section
# ===============================================================
# Do we or Don't we run GNU Parallel - test the circumstances and invoke nfdump

# we are told here outright to run or not run
if (($MasterPass eq "true") || ($passthru eq "true")) {
  my $timer = time;
  # Skip all further efforts if we are not enabled.
  # run the nfdump command as submitted with no performance improvements
  # Use the logcmd from above as this represents unmodified input
  system($logcmd) unless $DEBUG;
  print "MasterPass true mode in effect - We have run\n$logcmd\n" if $DEBUG;
  print $OUTPUT "========================================================= MasterPass true mode in effect - We have run\n$logcmd\n\n";
  my $duration = time - $timer;
  print $OUTPUT "========================================================= No Special Processing - Execution time: $duration s\n";
  close $OUTPUT;
  exit;
}

if ($opt_M) {
  # Process the directories from -M
  # populate array with directory list
  @DirList = &DirToArray();
  $dircount = @DirList;
  print "This is the expanded directory list \n" if $DEBUG;
  dump @DirList if $DEBUG;
  print "\n" if $DEBUG;
  print $OUTPUT "The expanded directory list is broken up to $dircount item(s)\n";
  print $OUTPUT @DirList if $Verbose;
  print $OUTPUT "\n\n" if $Verbose;
}

if ($opt_t) {
  # Process time range for -t
  # populate array with time ranges
  @TimeList = &TimeToArray();
  $timecount = @TimeList;
  print "This is the expanded time range list \n" if $DEBUG;
  dump @TimeList if $DEBUG;
  print "\n" if $DEBUG;
  print $OUTPUT "The expanded time range list is broken up to $timecount item(s)\n";
  print $OUTPUT @TimeList if $Verbose;
  print $OUTPUT "\n\n" if $Verbose;
}

# make one last go/nogo decision because if there is no reason to get fancy then don't
# If the array are single items, then just run nfdump
if (($dircount eq "1") && ($timecount eq "1")) {
  my $timer = time;
  # each array is one item long so just run the nfdump command
  system($logcmd) unless $DEBUG;
  print "No Parallel needed - one dir and one timelist is asked for\n" if $DEBUG;
  print "We have run\n$logcmd\n\n" if $DEBUG;
  print $OUTPUT "========================================================= No Parallel needed - one dir and one timelist is asked for\n";
  print $OUTPUT "========================================================= We have run\n$logcmd\n\n";
  my $duration = time - $timer;
  print $OUTPUT "========================================================= Parameters and Selections lead to No Special Processing - Execution time: $duration s\n";
  close $OUTPUT;
  exit;
}

# At this point we know we will use parallel execution
# So begin the GNU parallel tasks
#

# ================== So far there are 2 basic branches we need. 
# One is Top Talkers, the other is for everything else
# Top Talkers
# as for Top Talkers, skip it for now until we solve that puzzle
if ($toptalker eq "true") {
  my $timer = time;
  # A Top Talkers request is not able to use a binary output to an intermediate directory
  # So we need to run it and save the text outputs in an array or variable, 
  # and work with the data to create a final output

  $quefile = "no-queue";
 
  # write the parallel queue file using the arrays from -M and -t and any extended command syntax
  #print $OUTPUT "Will now run the sub MakeTopTalkersQueueFile\n\n" if $Verbose;
  #$quefile = &MakeTopTalkersQueueFile();
  #print "queue File $quefile\n" if $DEBUG;
  #print $OUTPUT "queue File $quefile\n\n" if $Verbose;

  # display the queue file so we can tell what would have run
  #&PrintFile($quefile) if $DEBUG;

  # Do the work by using the queue file
  # run parallel with proper parameters for Top Talkers
  print $OUTPUT "Will now run the sub RunTopTalkersParallel with $quefile\n\n" if $Verbose;
  &RunTopTalkersParallel($quefile);

  # deal with the output and send to NNA
  #print $OUTPUT "Will now run the sub RunTopTalkersFinalPass\n\n" if $Verbose;
  #&RunTopTalkersFinalPass();

  # Clean up any temporary files
  #print $OUTPUT "Will now run the sub RunCleanup\n\n" if $Verbose;
  #&RunCleanup();

  my $duration = time - $timer;
  print $OUTPUT "========================================================= Top Talkers - Execution time: $duration s\n";
  close $OUTPUT;
  exit;
} 

# we are not just passing thru...
if ($passthru eq "false") {
  my $timer = time;
  # continue with optimization for all other requests such as Chord Diagrams or other Queries

  # Do we have cached data
  #my $decision = &TestIntermediateDir($alltstamp);
  #if ($decision eq "false") {
    # carry on with normal steps - we have no cache to use

    # Make an intermediate directory
    print $OUTPUT "Will now run the sub MakeIntermediateDir\n\n" if $Verbose;
    &MakeIntermediateDir($tstamp);

    # write the parallel queue file using the arrays from above and any extended command syntax
    print $OUTPUT "Will now run the sub MakeQueueFile\n\n" if $Verbose;
    $quefile = &MakeQueueFile();
    print "queue File $quefile\n" if $DEBUG;
    print $OUTPUT "queue File $quefile\n\n" if $Verbose;

    # display the queue file so we can tell what would have run
    &PrintFile($quefile) if $DEBUG;

    # Do the work by using the queue file
    # run parallel with proper parameters for using an intermediate directory
    print $OUTPUT "Will now run the sub RunParallel with $quefile\n\n" if $Verbose;
    &RunParallel($quefile);
  #} # End of if so now we have cached data

  # Finish up the display of data
  print $OUTPUT "Will now run the sub RunFinalPass\n\n" if $Verbose;
  &RunFinalPass();

  # Clean up any temporary files - rethinking this as some cached data is useful
  print $OUTPUT "Will now run the sub RunCleanup\n\n" if $Verbose;
  &RunCleanup();

  my $duration = time - $timer;
  print $OUTPUT "========================================================= Intermediate Dir and Parallel Process - Execution time: $duration s\n";
  close $OUTPUT;
  exit;
}

# from here down are subroutines
exit;

# -----------------------------------------------------------------
# Define Subroutines
# -----------------------------------------------------------------

# =========================================================================
# =========================================== SECTION FOR INTERMEDIATE FILES
# =========================================================================

#-------------------------------------------------------------------------
sub MakeQueueFile() {
  my $extendparam = "";
  my $counter = "0";
  # open the parallel queue file for write
  my $queuefile = $QUEDIR . "queue." . $tstamp;
  print $OUTPUT "========================================================= Open Queue File open for writing $queuefile\n\n";
  print $OUTPUT "Queue File will be written to $queuefile\n\n";
  open(my $mfh, '>', "$queuefile") or print $OUTPUT "========================================================= Oops, we cannot open the queue file here - $queuefile $!\n";
  # iterate the dir and time arrays and write to the queue file
  foreach my $dir (@DirList) {
    foreach my $increment (@TimeList) {
      # make up incremental file names
      $counter++;
      my $filecounter = sprintf("%04d", $counter);
      $extendparam = "-w \'" . $NFDLOCATION . "nfdfile." . $tstamp . "-" . $filecounter . "\'";
      # Add to the final command line if there is a filter in use - the filter is always last
      if ($filter) {
        print $mfh "$command $extendparam -R \'$opt_R\' -M \'$dir\' -t \'$increment\' \'$filter\'\n";
        print $OUTPUT "$command $extendparam -R \'$opt_R\' -M \'$dir\' -t \'$increment\' \'$filter\'\n" if $Verbose;
      } else {
        print $mfh "$command $extendparam -R \'$opt_R\' -M \'$dir\' -t \'$increment\'\n";
        print $OUTPUT "$command $extendparam -R \'$opt_R\' -M \'$dir\' -t \'$increment\'\n" if $Verbose;
      }
    }
  }
  close $mfh;
  print $OUTPUT "closed the file $queuefile\n\n" if $Verbose;
  print $OUTPUT "========================================================= Queue file has $counter entries for Parallel\n\n";

  # return the queue file name
  return "$queuefile";
} # End of sub MakeQueueFile

#-------------------------------------------------------------------------
sub RunParallel($) {
  # This sub will prepare files for the Final Pass. It should have no STDOUT
  # queue file name
  my $que = shift;
  print "Parallel is Processing Queue File $que\n" if $DEBUG;
  print $OUTPUT "========================================================= Parallel is Processing Queue File $que\n\n";
  # the output needs to be hidden from display here so capture it to a variable
  my $parallelout = qx(cat $que | parallel -j +0 2>&1);
  print $OUTPUT "========================================================= Parallel qx (cat $que | parallel -j +0) has run\n\n";
} # End of sub RunParallel

#-------------------------------------------------------------------------
sub RunFinalPass() {
  # if we used the intermediate directory, then all our stuff is cached there waiting to display for NNA
  # we just need to run nfdump a special way. so lets do that by getting the command syntax correctly set.
  print $OUTPUT "Starting a Final Pass\n\n" if $Verbose;
  # we removed the -c from the smaller parallel runs for Chord Diagrams but add it back for the final pass
  if ($opt_c) {
    $command .= " -c \'$opt_c\'";
  }
  # for a final pass we use the intermediate directory to complete the command syntax
  if ($filter) {
    $command .= " -R \'.\' -M \'$NFDLOCATION\' -t \'$opt_t\' \'$filter\'";
  } else {
    $command .= " -R \'.\' -M \'$NFDLOCATION\' -t \'$opt_t\'";
  }
  # run the command and let the output go to NNA
  print $OUTPUT "========================================================= Running special nfdump to aggregate Intermediate file data\n";
  print $OUTPUT "========================================================= Running syntax is\n$command\n\n";
  system($command);
  print "DEBUG is on - parallel was run - this is a final pass to produce the final result\n$command\n\n" if $DEBUG;
  print $OUTPUT "Intermediate file data has been processed\n\n" if $Verbose;
} # End of sub RunFinalPass

# =========================================================================
# ===================================================== TOP TALKERS SECTION
# =========================================================================

#-------------------------------------------------------------------------
sub MakeTopTalkersQueueFile() {
  # open the parallel queue file for write
  my $queuefile = $QUEDIR . "queue." . $tstamp;
  print $OUTPUT "========================================================= Open Queue File open for writing $queuefile\n\n";
  open(my $mfh, '>', "$queuefile") 
    or print $OUTPUT "========================================================= Oops, we cannot open the queue file here - $queuefile $!\n";
  # iterate the dir and time arrays and write to the queue file
  foreach my $dir (@DirList) {
    foreach my $increment (@TimeList) {
      # Add to the final command line if there is a filter in use - the filter is always last
      if ($filter) {
        print $mfh "$command -R \'$opt_R\' -M \'$dir\' -t \'$increment\' \'$filter\'\n";
        print $OUTPUT "$command -R \'$opt_R\' -M \'$dir\' -t \'$increment\' \'$filter\'\n" if $Verbose;
      } else {
        print $mfh "$command -R \'$opt_R\' -M \'$dir\' -t \'$increment\'\n";
        print $OUTPUT "$command -R \'$opt_R\' -M \'$dir\' -t \'$increment\'\n" if $Verbose;
      }
    }
  }
  close $mfh;
  print $OUTPUT "closed the file $queuefile\n\n" if $Verbose;

  # return the queue file name
  return "$queuefile";
} # End of sub MakeTopTalkersQueueFile

#-------------------------------------------------------------------------
sub RunTopTalkersParallel($) {
  # This sub will deal with Top Talker preparation
  # get the queue file name
  my $que = shift;
  print "Top Talkers Queue File $que\n" if $DEBUG;
  print $OUTPUT "========================================================= Top Talkers Queue File $que\n\n";

  # for now - parallel processing is disabled or code is in process so revert to previous syntax
  print $OUTPUT "========================================================= No Parallel needed - Top Talker is asked for\n";
  system($logcmd) unless $DEBUG;
  print "No Parallel needed - Top Talker is asked for\n" if $DEBUG;
  print "We would have run\n$logcmd\n\n" if $DEBUG;
  print $OUTPUT "We would have run\n$logcmd\n\n" if $Verbose;
  # ====================================== temporary
  return;

  # if you comment out the return above then Dual methods wil be in use for code development

  # the output needs to be hidden from display here so capture it to a variable
  @toptalkersparallelout = qx(cat $que | parallel -j +0 2>&1);
  print $OUTPUT "========================================================= Parallel qx (cat $que | parallel -j +0) has run\n\n";
} # End of sub RunTopTalkersParallel

#-------------------------------------------------------------------------
sub RunTopTalkersFinalPass() {
  # Top Talker output has been captured to an array named @toptalkersparallelout
  # We need to process that and format the output to resemble the initial request
  print $OUTPUT "Starting a Top Talkers Final Pass\n\n" if $Verbose;

  # the top n header uses 'val'
  # ts,te,td,pr,val,fl,flP,pkt,pktP,byt,bytP,pps,bps,bpp
  # the 5th element aka [4]

  # my required variables
  my @toparray;
  my $flowtext;
  my $sumvals;
  my $headtext;

  # Process the contents of @toptalkersparallelout

  # read the data, 
  # consolidate and aggregate common items, 
  # put in order by bytes, 
  # reduce the final count of items to match the -n request
  # and output the result

  # output final data to NNA
  foreach my $row (@toptalkersparallelout) {
    chomp $row;
    # header text
    if ($row =~ m/^ts/) {
      $headtext = $row; 
    }
    # Date stamp formatting
    # This is the data that needs special processing
    elsif ($row =~ m/^(\d\d\d\d)-(\d\d)-(\d\d)/) {
      push (@toparray, $row);
    }
    # Summary text
    elsif ($row =~ m/^flows/) {
      $flowtext = $row; 
    }
    # Summary values
    elsif ($row =~ m/\d+/) {
      $sumvals = $row; 
    }
  }

  # Once toparray is processed send the expected output to NNA
    
  print $OUTPUT "$headtext\n" if $Verbose;

  # Temporary.............................................
  # in this shape "$ts,$te,$td,$pr,$val,$fl,$flP,$pkt,$pktP,$byt,$bytP,$pps,$bps,$bpp\n";
  # loop thru array and print output for the opt_n lines requested
  # print the lines in the array separated by commas
  &PrintArray(\@toparray) if $Verbose;

  # provide the expected closing syntax - used or unused I do not know - but does not work without.
  print $OUTPUT "\nSummary\n" if $Verbose;
  print $OUTPUT "$flowtext\n" if $Verbose;
  print $OUTPUT "$sumvals\n" if $Verbose;

  print "DEBUG is on - parallel may have been run - this final pass is to run\n$command\n\n" if $DEBUG;
  print $OUTPUT "Top Talkers output needs to be combined\n\n" if $Verbose;
} # End of sub RunTopTalkersFinalPass

# Information for Array Sort...
# You need the cmp for strings and the spaceship for numbers:
# my @sorted = sort { $a->[0] cmp $b->[0] || $a->[1] <=> $b->[1] } @data;


# ===============================================================
# ==================================== COMMON FUNCTIONS AND TOOLS
# ===============================================================


#-------------------------------------------------------------------------
sub MakeIntermediateDir($) {
  # make a directory for the intermediate nfdump binary files
  # the NFDLOCATION variable is populated here, used here, and used elsewhere
  my $dirtime = shift;
  $NFDLOCATION = $TMPDIR . "nfd." . $dirtime . "/";
  print $OUTPUT "Using $TMPDIR to create an Intermediate directory $NFDLOCATION\n\n" if $Verbose;
  print "Intermediate directory will be $NFDLOCATION\n" if $DEBUG;

  if (-e $NFDLOCATION) {
    print $OUTPUT "Existing Intermediate directory $NFDLOCATION is available\n\n" if $Verbose;
  } else {
    make_path($NFDLOCATION, { mode => 0755 });
    # test for success
    if (! -e $NFDLOCATION) {
      print $OUTPUT "Intermediate directory $NFDLOCATION is NOT available\n\n" if $Verbose;
    } else {
      print $OUTPUT "Intermediate directory $NFDLOCATION is available\n\n" if $Verbose;
    }
  }
  print $OUTPUT "End of MakeIntermediateDir\n\n" if $Verbose;
} # End of sub MakeIntermediateDir

#-------------------------------------------------------------------------
sub TestIntermediateDir($) {
  # use the time stamp and see if the location already exists
  my $dirtime = shift;
  my $test = $TMPDIR . "nfd." . $dirtime . "/";

  # Test and return true or false
  if (-e $test) {
    print $OUTPUT "Existing Intermediate directory $test is available\n\n" if $Verbose;
    return "true";
  } else {
    print $OUTPUT "Intermediate directory $test does not exist\n\n" if $Verbose;
    return "false";
  }
} # End of sub TestIntermediateDir

#-------------------------------------------------------------------------
sub RunCleanup() {
  # Add a slight delay and allow files to finish any activity that may still be running
  # ========================================================================================================= <=== Need work here SLB
  # Modify entire sub to look for files and dir older than 30 minutes
  # $QUEDIR $TMPDIR $LOGDIR
  sleep(2);
  {
    # to start over clean
    #remove_tree($TMPDIR);
    # to run normal
    remove_tree($NFDLOCATION);
    print $OUTPUT "removed intermediate location " . $NFDLOCATION  . "\n" if $Verbose;
  }

  {
    my $ctr = "0";
    # Clean up queue.* files in the $QUEDIR
    $CWD = $QUEDIR;
    # to delete all queue files and not the ones we just made
    #my $basefile = "queue.*";
    # to delete just the queue file we just made
    my $basefile = "queue." . $tstamp;
    print $OUTPUT "The file for deletion is " . $basefile  . "\n" if $Verbose;
    my @queuelist=<"$basefile">;
    foreach my $del (@queuelist) {
      unlink $del;
      $ctr++;
      print $OUTPUT "Deleted the " . $del  . " file\n" if $Verbose;
    }
    print $OUTPUT "Removed  " . $ctr  . " files\n" if $Verbose;
  }
} # End of sub RunCleanup

#-------------------------------------------------------------------------
sub PrintFile($) {
  my $filename = shift;
  open(my $pfh, '<', $filename)
    or print $OUTPUT "========================================================= Could not open the parallel queue file '$filename' $!";
  while (my $row = <$pfh>) {
    chomp $row;
    print "$row\n";
  }
  close $pfh;
} # End of sub PrintFile

#-------------------------------------------------------------------------
sub PrintArray(@) {
  my @array = @{$_[0]};
  foreach (@array) {
    print $OUTPUT $_ . "\n";
  }
} # End of sub PrintArray

#-------------------------------------------------------------------------
sub EpochToT($) {
  my $toconvert = shift;
  my ($sec,$min,$hour,$day,$month,$year) = localtime($toconvert);
  # correct the yar for humans
  $year = 1900 + $year;
  # Format for nfdump
  my $date = sprintf "%04d/%02d/%02d.%02d:%02d:%02d", $year, $month, $day, $hour, $min, $sec;
  return $date;
} # End of sub EpochToT

# -----------------------------------------------------------------
sub TimeToArray() {
  my @results;
  my $onehour = "3600"; # in seconds
  if (! $interval) {
    # Something is wrong up top so lets use 3
    $interval = 3;
  }
  # add a delay for processing the last time period. if it is small then combine it with the previous time period.
  #my $convdelay = "900"; # in seconds is 15 minutes
  #my $convdelay = "600"; # set to 10 minutes in seconds
  my $convdelay = "300"; # set to 10 minutes in seconds
  # Set number to increment by
  my $skip = $interval * $onehour;

  # -t '2017/06/27.11:42:51-2017/06/27.15:42:50'
  # take the -t parameter $opt_t and separate the start from the end
  my ($start,$end) = split("-", $opt_t);

  # Separate the elements
  my ($syear,$smonth,$sday,$shour,$sminute,$ssecond) = split /[\/\.:]/, $start;
  my ($eyear,$emonth,$eday,$ehour,$eminute,$esecond) = split /[\/\.:]/, $end;

  # Convert to Epoch
  my $initialstart = timelocal($ssecond,$sminute,$shour,$sday,$smonth,$syear);
  my $initialend = timelocal($esecond,$eminute,$ehour,$eday,$emonth,$eyear);

  # make working times for the loop
  my $workingstart = $initialstart;
  my $workingend = $initialstart + $skip;
  # Start loop to step through time intervals
  do {
    # Convert Epoch to -t format
    my $displaystart = &EpochToT($workingstart);
    my $displayend = &EpochToT($workingend);
    # Do not exceed the original end time - first time through the loop
    if ($workingend > $initialend) {
      push (@results, $displaystart . "-" . $end);
    # This will be the most used section - but - special case is if the final time is a very small interval
    # try to not have a very small time period at the end - combine it with the previos time instead
    } elsif ($workingend + $skip + $convdelay < $initialend) {
      push (@results, $displaystart . "-" . $displayend);
    # seems like we must be finished so close off the last time period
    } else {
      push (@results, $displaystart . "-" . $end);
    }
    $workingstart = $workingend + 1;
    $workingend += $skip;
  } while ($initialend > $workingend);
  print $OUTPUT "Completed the time range expansion\n\n" if $Verbose;
  return @results;
} # End of sub TimeToArray

# -----------------------------------------------------------------
sub DirToArray() {
  # take the -M parameter $opt_M and return an array of directories
  my @dirlist = split(":", $opt_M);
  my @results;
  #
  # remember the first dir as that is the fully qualified one
  # There is no need to process it as it is absolute already
  my $base = shift @dirlist;
  push (@results, $base);
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
} # End of sub DirToArray


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
