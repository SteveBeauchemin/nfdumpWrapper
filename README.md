# nfdumpWrapper
A wrapper for nfdump that makes use of GNU parallel and makes use of all your host CPU

This is developed for use with Nagios Network Analyzer but should be easily expanded to work transparently
with any application that invokes nfdump.

The wrapper works by taking the initial command line invoked for nfdump and breaking it into smaller tasks. These tasks can be run in parallel with each other, and the output aggregated to provide the initial requested data. 

The syntax of certain nfdump parameters lend themselves to being broken into smaller pieces. Look at the man page for nfdump at the -t and the -M parameters. Also check out the -w parameter. Using this information I create multiple lines of nfdump commands that can be run in parallel. The binary results are saved in intermediate files. Then I run the original command against the intermediate files. The initial multi line nfdump commands are run using GNU parallel. The final pass is run against the intermediate binary results. The initial size of data could be many hundreds of gigabytes. The intermediate file size will be much smaller and as a result run very fast.

Prequisite Perl Modules:

Getopt::Long

Date::Format

Time::Local

File::Basename

File::chdir

File::Path

File::Remove

Data::Dump

Cwd

Prequisite Software:

GNU Parallel 

From

  https://www.gnu.org/software/parallel/

nfdump

From 

  https://github.com/phaag/nfdump           for version 1.6.15

  https://sourceforge.net/projects/nfdump/  for version 1.6.13

Installation:

To transparently invoke the wrapper, rename the current nfdump file, and replace it with the wrapper script.
I did this as follows. Feel free to improvise. I did.

Make a location for the perl script.

mkdir /usr/local/nfdumpWrapper

mkdir /usr/local/nfdumpWrapper/log


Now, hide the original nfdump my renaming it and prefixing a dot to the name.

mv /usr/local/bin/nfdump /usr/local/bin/.nfdump


Put the wrapper in place of nfdump by linking to the original location.

ln -s /usr/local/nfdumpWrapper/NFDump-wrapper.pl /usr/local/bin/nfdump


Make sure that the log location can be written to. Do this however you like. I know 777 is not preferred.

chmod 777 /usr/local/nfdumpWrapper/log


Possible problems:

I encountered a situation where the httpd process runs in a protected space. I that space it has a private /tmp location. I did not figure this out initially, so when I did find a solution I took the easy way out. The system I run this on is Red Hat 7. The httpd process creates a protected directory in /tmp. Maybe you have seen and wondered what that was for. I ignored it until it prevented me from doing what I needed.


In the /tmp directory you will see information like this:

drwx------ 3 root root 16 Jun 15 04:58 systemd-private-03d2c892c043485883d4e9e39bcd699a-httpd.service-V47y1Q

drwx------ 3 root root 16 Jun 15 04:57 systemd-private-03d2c892c043485883d4e9e39bcd699a-ntpd.service-gsx5YF


In the /tmp directory with httpd in the name is another tmp directory that is the protected space. I found that it was difficult to deal with files hidden there and decided to run httpd in unprotected space. This was done as follows:

cp /usr/lib/systemd/system/httpd.service /etc/systemd/system/httpd.service

vi /etc/systemd/system/httpd.service

Change the line from

PrivateTmp=true

to

PrivateTmp=false


Then tell the OS that you changed a startup file

systemctl daemon-reload


Then, stop and start httpd

systemctl stop httpd.service

systemctl start httpd.service


I also stopped the NNA and restarted it

systemctl stop nagiosna

systemctl start nagiosna


At this time, the httpd locked down directory in /tmp should be gone.


The perl script can now use /tmp to make intermediate files and queue files. I should clean up after itself.


Information:

http://nfdump.sourceforge.net/

