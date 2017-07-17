# nfdumpWrapper
A wrapper for nfdump that makes use of GNU parallel and makes use of all your host CPU

This is developed for use with Nagios Network Analyzer but should be easily expanded to work transparantly
with any application that invokes nfdump with multiple command line parameters.

The wrapper works by taking the command line invoked for nfdump and breaking the job into smaller tasks. These tasks can be run in parallel with each other, and the output aggregated to provide the initial requested data. Thsi is done by making use of GNU parallel software. Acquire from here https://www.gnu.org/software/parallel/

The syntax of certain parameters lend themselves to being broken into smaller pieces. Look at the man page for nfdump at the -t and the -M parameters. Also check oput the -w parameter. Using this information I create multiple lines of nfdump commands that need to run, and save the binary results in an intermediat for. Then I run the original command against the binary files. The initial multi line nfdump commands are run using GNU parallel. The final pass is run against the binary results or that list. The initial size of data could be many hundreds of gigabytes. The intermediat file size will be much smaller and as a result run very fast.

