# nfdumpWrapper
A wrapper for nfdump that makes use of GNU parallel and makes use of all your host CPU.<BR>
This is developed for use with Nagios Network Analyzer but should be easily expanded to work transparently with any application that invokes nfdump.<BR>
The wrapper works by taking the initial command line invoked for nfdump and breaking it into smaller tasks. These tasks can be run in parallel with each other, and the output aggregated to provide the initial requested data.<BR>
The syntax of certain nfdump parameters lend themselves to being broken into smaller pieces. Look at the man page for nfdump at the -t and the -M parameters. Also check out the -w parameter. Using this information I create multiple lines of nfdump commands that can be run in parallel. The binary results are saved in intermediate files. Then I run the original command against the intermediate files. The initial multi line nfdump commands are run using GNU parallel. The final pass is run against the intermediate binary results. The initial size of data could be many hundreds of gigabytes. The intermediate file size will be much smaller and as a result run very fast.<BR><BR>
Prequisite Perl Modules:<BR>
Getopt::Long<BR>
Date::Format<BR>
Time::Local<BR>
File::Basename<BR>
File::chdir<BR>
File::Path<BR>
File::Remove<BR>
Data::Dump<BR>
Cwd<BR>
<BR>
Prequisite Software:<BR>
GNU Parallel <BR>
From<BR>
  https://www.gnu.org/software/parallel/<BR>
<BR>
nfdump<BR>
From <BR>
  https://github.com/phaag/nfdump           for version 1.6.15<BR>
  https://sourceforge.net/projects/nfdump/  for version 1.6.13<BR>
<BR>
Installation:<BR>
To transparently invoke the wrapper, rename the current nfdump file, and replace it with the wrapper script. I did this as follows. Feel free to improvise. I did.<BR>
<BR>
Make locations for the perl script and the log data.<BR>
mkdir /usr/local/nfdumpWrapper<BR>
mkdir /usr/local/nfdumpWrapper/log<BR>
<BR>
Copy the wrapper to the new location.<BR>
cp NFDump-wrapper.pl /usr/local/nfdumpWrapper<BR>
<BR>
Make sure the wrapper is executable.<BR>
chmod 755 /usr/local/nfdumpWrapper/NFDump-wrapper.pl<BR>
<BR>
Now, hide the original nfdump my renaming it and prefixing a dot to the name.<BR>
mv /usr/local/bin/nfdump /usr/local/bin/.nfdump<BR>
<BR>
Put the wrapper in place of nfdump by linking to the original location.<BR>
ln -s /usr/local/nfdumpWrapper/NFDump-wrapper.pl /usr/local/bin/nfdump<BR>
<BR>
Make sure that the log location can be written to. Do this however you like. I know 777 is not preferred.<BR>
chmod 777 /usr/local/nfdumpWrapper/log<BR>
<BR>
Possible problems:<BR>
I encountered a situation where the httpd process runs in a protected space. In that space there is a private tmp directory. The httpd process thinks this is a root based /tmp location. I did not figure this out initially, so when I did find a solution I took the easy way out. The system I run this on is Red Hat 7. The httpd process creates a protected directory in /tmp using a long convoluted name. Maybe you have seen and wondered what that was for. I ignored it until it prevented me from doing what I needed.<BR>
<BR>
In the /tmp directory you will see information like this:<BR>
drwx------ 3 root root 16 Jun 15 04:58 systemd-private-03d2c892c043485883d4e9e39bcd699a-httpd.service-V47y1Q<BR>
<BR>
In that directory with httpd in the name is another tmp directory that is the protected space. I found that it was difficult to deal with files hidden there and decided to run httpd in unprotected space. This was done as follows:<BR>
cp /usr/lib/systemd/system/httpd.service /etc/systemd/system/httpd.service<BR>
vi /etc/systemd/system/httpd.service<BR>
Change the line from<BR>
PrivateTmp=true<BR>
to<BR>
PrivateTmp=false<BR>
<BR>
Tell the OS that you changed a startup file.<BR>
systemctl daemon-reload<BR>
<BR>
Stop and start httpd<BR>
systemctl stop httpd.service<BR>
systemctl start httpd.service<BR>
<BR>
I also stopped the NNA and restarted it<BR>
systemctl stop nagiosna<BR>
systemctl start nagiosna<BR>
<BR>
At this time, the httpd locked down directory in /tmp should be gone.<BR>
<BR>
The perl script can now use /tmp to make intermediate files and queue files. I should clean up after itself.<BR>
<BR>
Information:<BR>
http://nfdump.sourceforge.net/<BR>

