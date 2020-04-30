#!/bin/bash

kibana="<KIBANA-IP-ADDRESS>"
ls_ip1="<LOGSTASH-IP-ADDRESS>"
ls_ip2="<LOGSTASH-IP-ADDRESS>"

#Metricbeat
curl -L -O https://artifacts.elastic.co/downloads/beats/metricbeat/metricbeat-7.6.2-amd64.deb
sudo dpkg -i metricbeat-7.6.2-amd64.deb
sudo metricbeat modules enable system
#disable elasticsearch output
sudo sed -i 's/^output.elasticsearch\:/#&/' /etc/metricbeat/metricbeat.yml
sudo sed -i 's/^\ \ hosts\: \[\"localhost\:9200\"\]/#&/' /etc/metricbeat/metricbeat.yml
#add kibana host
sudo sed -i "s/^\ \ #host\: \"localhost\:5601\"/host\: \"$kibana\:5601\"/g" /etc/metricbeat/metricbeat.yml
#enable logstash output
sudo sed -i '/output.logstash\:/s/^#//g' /etc/metricbeat/metricbeat.yml
sudo sed -i "s/#hosts\: \[\"localhost\:5044\"\]/hosts\: \[\"$ls_ip2\:5044\"\]/g" /etc/metricbeat/metricbeat.yml
#activate metricbeat
sudo service metricbeat start

#Filebeat
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-7.6.2-amd64.deb
sudo dpkg -i filebeat-7.6.2-amd64.deb
#disable elasticsearch output
sudo sed -i 's/^output.elasticsearch\:/#&/' /etc/filebeat/filebeat.yml
sudo sed -i 's/^\ \ hosts\: \[\"localhost\:9200\"\]/#&/' /etc/filebeat/filebeat.yml
#add kibana host
sudo sed -i "s/^\ \ #host\: \"localhost\:5601\"/host\: \"$kibana\:5601\"/g" /etc/filebeat/filebeat.yml
#enable logstash output
sudo sed -i '/output.logstash\:/s/^#//g' /etc/filebeat/filebeat.yml
sudo sed -i "s/#hosts\: \[\"localhost\:5044\"\]/hosts\: \[\"$ls_ip1\:5044\"\]/g" /etc/filebeat/filebeat.yml
#enable system module
filebeat setup --pipelines --modules system
#activate metricbeat
sudo service filebeat start

#Packetbeat
sudo apt-get install libpcap0.8
curl -L -O https://artifacts.elastic.co/downloads/beats/packetbeat/packetbeat-7.6.2-amd64.deb
sudo dpkg -i packetbeat-7.6.2-amd64.deb
#disable elasticsearch output
sudo sed -i 's/^output.elasticsearch\:/#&/' /etc/packetbeat/packetbeat.yml
sudo sed -i 's/^\ \ hosts\: \[\"localhost\:9200\"\]/#&/' /etc/packetbeat/packetbeat.yml
#add kibana host
sudo sed -i "s/^\ \ #host\: \"localhost\:5601\"/host\: \"$kibana\:5601\"/g" /etc/packetbeat/packetbeat.yml
#enable logstash output
sudo sed -i '/output.logstash\:/s/^#//g' /etc/packetbeat/packetbeat.yml
sudo sed -i "s/#hosts\: \[\"localhost\:5044\"\]/hosts\: \[\"$ls_ip1\:5044\"\]/g" /etc/packetbeat/packetbeat.yml
#activate metricbeat
sudo service packetbeat start

#Auditbeat
curl -L -O https://artifacts.elastic.co/downloads/beats/auditbeat/auditbeat-7.6.2-amd64.deb
sudo dpkg -i auditbeat-7.6.2-amd64.deb
#Install auditd
sudo apt install -y auditd audispd-plugins
# Remove any existing rules
sudo auditctl -D

# Buffer Size
## Feel free to increase this if the machine panic's
sudo auditctl -b 8192

# Failure Mode
## Possible values: 0 (silent), 1 (printk, print a failure message), 2 (panic, halt the system)
sudo auditctl -f 1

# Ignore errors
## e.g. caused by users or files not found in the local environment  
sudo auditctl -i 

# Self Auditing ---------------------------------------------------------------

## Audit the audit logs
### Successful and unsuccessful attempts to read information from the audit records
sudo auditctl -w /var/log/audit/ -k auditlog

## Auditd configuration
### Modifications to audit configuration that occur while the audit collection functions are operating
sudo auditctl -w /etc/audit/ -p wa -k auditconfig
sudo auditctl -w /etc/libaudit.conf -p wa -k auditconfig
sudo auditctl -w /etc/audisp/ -p wa -k audispconfig

## Monitor for use of audit management tools
sudo auditctl -w /sbin/auditctl -p x -k audittools
sudo auditctl -w /sbin/auditd -p x -k audittools

# Filters ---------------------------------------------------------------------

### We put these early because audit is a first match wins system.

## Ignore SELinux AVC records
sudo auditctl -a always,exclude -F msgtype=AVC

## Ignore current working directory records
sudo auditctl -a always,exclude -F msgtype=CWD

## Ignore EOE records (End Of Event, not needed)
sudo auditctl -a always,exclude -F msgtype=EOE

## Cron jobs fill the logs with stuff we normally don't want (works with SELinux)
sudo auditctl -a never,user -F subj_type=crond_t
sudo auditctl -a exit,never -F subj_type=crond_t

## This prevents chrony from overwhelming the logs
sudo auditctl -a never,exit -F arch=b64 -S adjtimex -F auid=unset -F uid=chrony -F subj_type=chronyd_t

## This is not very interesting and wastes a lot of space if the server is public facing
sudo auditctl -a always,exclude -F msgtype=CRYPTO_KEY_USER

## VMWare tools
sudo auditctl -a exit,never -F arch=b32 -S fork -F success=0 -F path=/usr/lib/vmware-tools -F subj_type=initrc_t -F exit=-2
sudo auditctl -a exit,never -F arch=b64 -S fork -F success=0 -F path=/usr/lib/vmware-tools -F subj_type=initrc_t -F exit=-2

### High Volume Event Filter (especially on Linux Workstations)
sudo auditctl -a exit,never -F arch=b32 -F dir=/dev/shm -k sharedmemaccess
sudo auditctl -a exit,never -F arch=b64 -F dir=/dev/shm -k sharedmemaccess
sudo auditctl -a exit,never -F arch=b32 -F dir=/var/lock/lvm -k locklvm
sudo auditctl -a exit,never -F arch=b64 -F dir=/var/lock/lvm -k locklvm

# Rules -----------------------------------------------------------------------

## Kernel parameters
sudo auditctl -w /etc/sysctl.conf -p wa -k sysctl

## Kernel module loading and unloading
sudo auditctl -a always,exit -F perm=x -F auid!=-1 -F path=/sbin/insmod -k modules
sudo auditctl -a always,exit -F perm=x -F auid!=-1 -F path=/sbin/modprobe -k modules
sudo auditctl -a always,exit -F perm=x -F auid!=-1 -F path=/sbin/rmmod -k modules
sudo auditctl -a always,exit -F arch=b64 -S finit_module -S init_module -S delete_module -F auid!=-1 -k modules
sudo auditctl -a always,exit -F arch=b32 -S finit_module -S init_module -S delete_module -F auid!=-1 -k modules
## Modprobe configuration
sudo auditctl -w /etc/modprobe.conf -p wa -k modprobe

## KExec usage (all actions)
sudo auditctl -a always,exit -F arch=b64 -S kexec_load -k KEXEC
sudo auditctl -a always,exit -F arch=b32 -S sys_kexec_load -k KEXEC

## Special files
sudo auditctl -a exit,always -F arch=b32 -S mknod -S mknodat -k specialfiles
sudo auditctl -a exit,always -F arch=b64 -S mknod -S mknodat -k specialfiles

## Mount operations (only attributable)
sudo auditctl -a always,exit -F arch=b64 -S mount -S umount2 -F auid!=-1 -k mount
sudo auditctl -a always,exit -F arch=b32 -S mount -S umount -S umount2 -F auid!=-1 -k mount

# Change swap (only attributable)
sudo auditctl -a always,exit -F arch=b64 -S swapon -S swapoff -F auid!=-1 -k swap
sudo auditctl -a always,exit -F arch=b32 -S swapon -S swapoff -F auid!=-1 -k swap

## Time
sudo auditctl -a exit,always -F arch=b32 -S adjtimex -S settimeofday -S clock_settime -k time
sudo auditctl -a exit,always -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time
### Local time zone
sudo auditctl -w /etc/localtime -p wa -k localtime

## Stunnel
sudo auditctl -w /usr/sbin/stunnel -p x -k stunnel

## Cron configuration & scheduled jobs
sudo auditctl -w /etc/cron.allow -p wa -k cron
sudo auditctl -w /etc/cron.deny -p wa -k cron
sudo auditctl -w /etc/cron.d/ -p wa -k cron
sudo auditctl -w /etc/cron.daily/ -p wa -k cron
sudo auditctl -w /etc/cron.hourly/ -p wa -k cron
sudo auditctl -w /etc/cron.monthly/ -p wa -k cron
sudo auditctl -w /etc/cron.weekly/ -p wa -k cron
sudo auditctl -w /etc/crontab -p wa -k cron
sudo auditctl -w /var/spool/cron/crontabs/ -k cron

## User, group, password databases
sudo auditctl -w /etc/group -p wa -k etcgroup
sudo auditctl -w /etc/passwd -p wa -k etcpasswd
sudo auditctl -w /etc/gshadow -k etcgroup
sudo auditctl -w /etc/shadow -k etcpasswd
sudo auditctl -w /etc/security/opasswd -k opasswd

## Sudoers file changes
sudo auditctl -w /etc/sudoers -p wa -k actions

## Passwd
sudo auditctl -w /usr/bin/passwd -p x -k passwd_modification

## Tools to change group identifiers
sudo auditctl -w /usr/sbin/groupadd -p x -k group_modification
sudo auditctl -w /usr/sbin/groupmod -p x -k group_modification
sudo auditctl -w /usr/sbin/addgroup -p x -k group_modification
sudo auditctl -w /usr/sbin/useradd -p x -k user_modification
sudo auditctl -w /usr/sbin/usermod -p x -k user_modification
sudo auditctl -w /usr/sbin/adduser -p x -k user_modification

## Login configuration and information
sudo auditctl -w /etc/login.defs -p wa -k login
sudo auditctl -w /etc/securetty -p wa -k login
sudo auditctl -w /var/log/faillog -p wa -k login
sudo auditctl -w /var/log/lastlog -p wa -k login
sudo auditctl -w /var/log/tallylog -p wa -k login

## Network Environment
### Changes to hostname
sudo auditctl -a always,exit -F arch=b32 -S sethostname -S setdomainname -k network_modifications
sudo auditctl -a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_modifications
### Changes to other files
sudo auditctl -w /etc/hosts -p wa -k network_modifications
sudo auditctl -w /etc/sysconfig/network -p wa -k network_modifications
sudo auditctl -w /etc/network/ -p wa -k network
sudo auditctl -a always,exit -F dir=/etc/NetworkManager/ -F perm=wa -k network_modifications
sudo auditctl -w /etc/sysconfig/network -p wa -k network_modifications
### Changes to issue
sudo auditctl -w /etc/issue -p wa -k etcissue
sudo auditctl -w /etc/issue.net -p wa -k etcissue

## System startup scripts
sudo auditctl -w /etc/inittab -p wa -k init
sudo auditctl -w /etc/init.d/ -p wa -k init
sudo auditctl -w /etc/init/ -p wa -k init

## Library search paths
sudo auditctl -w /etc/ld.so.conf -p wa -k libpath

## Pam configuration
sudo auditctl -w /etc/pam.d/ -p wa -k pam
sudo auditctl -w /etc/security/limits.conf -p wa  -k pam
sudo auditctl -w /etc/security/pam_env.conf -p wa -k pam
sudo auditctl -w /etc/security/namespace.conf -p wa -k pam
sudo auditctl -w /etc/security/namespace.init -p wa -k pam

## Postfix configuration
sudo auditctl -w /etc/aliases -p wa -k mail
sudo auditctl -w /etc/postfix/ -p wa -k mail

## SSH configuration
sudo auditctl -w /etc/ssh/sshd_config -k sshd

# Systemd
sudo auditctl -w /bin/systemctl -p x -k systemd 
sudo auditctl -w /etc/systemd/ -p wa -k systemd

## SELinux events that modify the system's Mandatory Access Controls (MAC)
sudo auditctl -w /etc/selinux/ -p wa -k mac_policy

## Critical elements access failures 
sudo auditctl -a exit,always -F arch=b64 -S open -F dir=/etc -F success=0 -k unauthedfileaccess
sudo auditctl -a exit,always -F arch=b64 -S open -F dir=/bin -F success=0 -k unauthedfileaccess
sudo auditctl -a exit,always -F arch=b64 -S open -F dir=/sbin -F success=0 -k unauthedfileaccess
sudo auditctl -a exit,always -F arch=b64 -S open -F dir=/usr/bin -F success=0 -k unauthedfileaccess
sudo auditctl -a exit,always -F arch=b64 -S open -F dir=/usr/sbin -F success=0 -k unauthedfileaccess
sudo auditctl -a exit,always -F arch=b64 -S open -F dir=/var -F success=0 -k unauthedfileaccess
sudo auditctl -a exit,always -F arch=b64 -S open -F dir=/home -F success=0 -k unauthedfileaccess
sudo auditctl -a exit,always -F arch=b64 -S open -F dir=/srv -F success=0 -k unauthedfileaccess

## Process ID change (switching accounts) applications
sudo auditctl -w /bin/su -p x -k priv_esc
sudo auditctl -w /usr/bin/sudo -p x -k priv_esc
sudo auditctl -w /etc/sudoers -p rw -k priv_esc

## Power state
sudo auditctl -w /sbin/shutdown -p x -k power
sudo auditctl -w /sbin/poweroff -p x -k power
sudo auditctl -w /sbin/reboot -p x -k power
sudo auditctl -w /sbin/halt -p x -k power

## Session initiation information
sudo auditctl -w /var/run/utmp -p wa -k session
sudo auditctl -w /var/log/btmp -p wa -k session
sudo auditctl -w /var/log/wtmp -p wa -k session

## Discretionary Access Control (DAC) modifications
sudo auditctl -a always,exit -F arch=b32 -S chmod -F auid>=500 -F auid!=4294967295 -k perm_mod
sudo auditctl -a always,exit -F arch=b32 -S chown -F auid>=500 -F auid!=4294967295 -k perm_mod
sudo auditctl -a always,exit -F arch=b32 -S fchmod -F auid>=500 -F auid!=4294967295 -k perm_mod
sudo auditctl -a always,exit -F arch=b32 -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
sudo auditctl -a always,exit -F arch=b32 -S fchown -F auid>=500 -F auid!=4294967295 -k perm_mod
sudo auditctl -a always,exit -F arch=b32 -S fchownat -F auid>=500 -F auid!=4294967295 -k perm_mod
sudo auditctl -a always,exit -F arch=b32 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
sudo auditctl -a always,exit -F arch=b32 -S fsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
sudo auditctl -a always,exit -F arch=b32 -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
sudo auditctl -a always,exit -F arch=b32 -S lremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
sudo auditctl -a always,exit -F arch=b32 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
sudo auditctl -a always,exit -F arch=b32 -S removexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
sudo auditctl -a always,exit -F arch=b32 -S setxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
sudo auditctl -a always,exit -F arch=b64 -S chmod  -F auid>=500 -F auid!=4294967295 -k perm_mod
sudo auditctl -a always,exit -F arch=b64 -S chown -F auid>=500 -F auid!=4294967295 -k perm_mod
sudo auditctl -a always,exit -F arch=b64 -S fchmod -F auid>=500 -F auid!=4294967295 -k perm_mod
sudo auditctl -a always,exit -F arch=b64 -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
sudo auditctl -a always,exit -F arch=b64 -S fchown -F auid>=500 -F auid!=4294967295 -k perm_mod
sudo auditctl -a always,exit -F arch=b64 -S fchownat -F auid>=500 -F auid!=4294967295 -k perm_mod
sudo auditctl -a always,exit -F arch=b64 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
sudo auditctl -a always,exit -F arch=b64 -S fsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
sudo auditctl -a always,exit -F arch=b64 -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
sudo auditctl -a always,exit -F arch=b64 -S lremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
sudo auditctl -a always,exit -F arch=b64 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
sudo auditctl -a always,exit -F arch=b64 -S removexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
sudo auditctl -a always,exit -F arch=b64 -S setxattr -F auid>=500 -F auid!=4294967295 -k perm_mod

# Special Rules ---------------------------------------------------------------

## 32bit API Exploitation
### If you are on a 64 bit platform, everything _should_ be running
### in 64 bit mode. This rule will detect any use of the 32 bit syscalls
### because this might be a sign of someone exploiting a hole in the 32
### bit API.
sudo auditctl -a always,exit -F arch=b32 -S all -k 32bit_api

## Reconnaissance
sudo auditctl -w /usr/bin/whoami -p x -k recon
sudo auditctl -w /etc/issue -p r -k recon
sudo auditctl -w /etc/hostname -p r -k recon

## Suspicious activity
sudo auditctl -w /usr/bin/wget -p x -k susp_activity
sudo auditctl -w /usr/bin/curl -p x -k susp_activity
sudo auditctl -w /usr/bin/base64 -p x -k susp_activity
sudo auditctl -w /bin/nc -p x -k susp_activity
sudo auditctl -w /bin/netcat -p x -k susp_activity
sudo auditctl -w /usr/bin/ncat -p x -k susp_activity
sudo auditctl -w /usr/bin/ssh -p x -k susp_activity
sudo auditctl -w /usr/bin/socat -p x -k susp_activity
sudo auditctl -w /usr/bin/wireshark -p x -k susp_activity
sudo auditctl -w /usr/bin/rawshark -p x -k susp_activity
sudo auditctl -w /usr/bin/rdesktop -p x -k sbin_susp

## Sbin suspicious activity
sudo auditctl -w /sbin/iptables -p x -k sbin_susp 
sudo auditctl -w /sbin/ifconfig -p x -k sbin_susp
sudo auditctl -w /usr/sbin/tcpdump -p x -k sbin_susp
sudo auditctl -w /usr/sbin/traceroute -p x -k sbin_susp

## Injection 
### These rules watch for code injection by the ptrace facility.
### This could indicate someone trying to do something bad or just debugging
sudo auditctl -a always,exit -F arch=b32 -S ptrace -k tracing
sudo auditctl -a always,exit -F arch=b64 -S ptrace -k tracing
sudo auditctl -a always,exit -F arch=b32 -S ptrace -F a0=0x4 -k code_injection
sudo auditctl -a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k code_injection
sudo auditctl -a always,exit -F arch=b32 -S ptrace -F a0=0x5 -k data_injection
sudo auditctl -a always,exit -F arch=b64 -S ptrace -F a0=0x5 -k data_injection
sudo auditctl -a always,exit -F arch=b32 -S ptrace -F a0=0x6 -k register_injection
sudo auditctl -a always,exit -F arch=b64 -S ptrace -F a0=0x6 -k register_injection

## Privilege Abuse
### The purpose of this rule is to detect when an admin may be abusing power by looking in user's home dir.
sudo auditctl -a always,exit -F dir=/home -F uid=0 -F auid>=1000 -F auid!=4294967295 -C auid!=obj_uid -k power_abuse

# Software Management ---------------------------------------------------------

# DPKG / APT-GET (Debian/Ubuntu)
sudo auditctl -w /usr/bin/dpkg -p x -k software_mgmt
sudo auditctl -w /usr/bin/apt-add-repository -p x -k software_mgmt
sudo auditctl -w /usr/bin/apt-get -p x -k software_mgmt
sudo auditctl -w /usr/bin/aptitude -p x -k software_mgmt

# High volume events ----------------------------------------------------------

## Remove them if the cause to much volumen in your einvironment

## Root command executions 
sudo auditctl -a exit,always -F arch=b64 -F euid=0 -S execve -k rootcmd
sudo auditctl -a exit,always -F arch=b32 -F euid=0 -S execve -k rootcmd

## File Deletion Events by User
sudo auditctl -a always,exit -F arch=b32 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
sudo auditctl -a always,exit -F arch=b64 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete

## File Access
### Unauthorized Access (unsuccessful)
sudo auditctl -a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k file_access
sudo auditctl -a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k file_access
sudo auditctl -a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k file_access
sudo auditctl -a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k file_access

### Unsuccessful Creation
sudo auditctl -a always,exit -F arch=b32 -S creat,link,mknod,mkdir,symlink,mknodat,linkat,symlinkat -F exit=-EACCES -k file_creation
sudo auditctl -a always,exit -F arch=b64 -S mkdir,creat,link,symlink,mknod,mknodat,linkat,symlinkat -F exit=-EACCES -k file_creation
sudo auditctl -a always,exit -F arch=b32 -S link,mkdir,symlink,mkdirat -F exit=-EPERM -k file_creation
sudo auditctl -a always,exit -F arch=b64 -S mkdir,link,symlink,mkdirat -F exit=-EPERM -k file_creation

### Unsuccessful Modification
sudo auditctl -a always,exit -F arch=b32 -S rename -S renameat -S truncate -S chmod -S setxattr -S lsetxattr -S removexattr -S lremovexattr -F exit=-EACCES -k file_modification
sudo auditctl -a always,exit -F arch=b64 -S rename -S renameat -S truncate -S chmod -S setxattr -S lsetxattr -S removexattr -S lremovexattr -F exit=-EACCES -k file_modification
sudo auditctl -a always,exit -F arch=b32 -S rename -S renameat -S truncate -S chmod -S setxattr -S lsetxattr -S removexattr -S lremovexattr -F exit=-EPERM -k file_modification
sudo auditctl -a always,exit -F arch=b64 -S rename -S renameat -S truncate -S chmod -S setxattr -S lsetxattr -S removexattr -S lremovexattr -F exit=-EPERM -k file_modification

#disable elasticsearch output
sudo sed -i 's/^output.elasticsearch\:/#&/' /etc/auditbeat/auditbeat.yml
sudo sed -i 's/^\ \ hosts\: \[\"localhost\:9200\"\]/#&/' /etc/auditbeat/auditbeat.yml
#add kibana host
sudo sed -i "s/^\ \ #host\: \"localhost\:5601\"/host\: \"$kibana\:5601\"/g" /etc/auditbeat/auditbeat.yml
#enable logstash output
sudo sed -i '/output.logstash\:/s/^#//g' /etc/auditbeat/auditbeat.yml
sudo sed -i "s/#hosts\: \[\"localhost\:5044\"\]/hosts\: \[\"$ls_ip2\:5044\"\]/g" /etc/auditbeat/auditbeat.yml

#Start Auditbeat
sudo systemctl start auditbeat
sudo systemctl enable auditbeat