#!/bin/bash
mkdir -p /tmp/filematrix && cd /tmp/filematrix
#---------------------------------------------------------------------
cat << EOF >> /tmp/filematrix/filematrix_rhel8.txt
/etc/audit
/etc/audit/auditd.conf
/etc/audit/rules.d
/etc/audit/rules.d/audit.rules
/etc/login.defs
/etc/pam.d
/etc/pam.d/atd
/etc/pam.d/chfn
/etc/pam.d/chsh
/etc/pam.d/cockpit
/etc/pam.d/config-util
/etc/pam.d/crond
/etc/pam.d/cups
/etc/pam.d/gdm-autologin
/etc/pam.d/gdm-fingerprint
/etc/pam.d/gdm-launch-environment
/etc/pam.d/gdm-password
/etc/pam.d/gdm-pin
/etc/pam.d/gdm-smartcard
/etc/pam.d/ksu
/etc/pam.d/login
/etc/pam.d/other
/etc/pam.d/passwd
/etc/pam.d/pluto
/etc/pam.d/polkit-1
/etc/pam.d/remote
/etc/pam.d/runuser
/etc/pam.d/runuser-l
/etc/pam.d/samba
/etc/pam.d/screen
/etc/pam.d/smtp
/etc/pam.d/smtp.postfix
/etc/pam.d/sshd
/etc/pam.d/sssd-shadowutils
/etc/pam.d/su
/etc/pam.d/subscription-manager
/etc/pam.d/sudo
/etc/pam.d/sudo-i
/etc/pam.d/su-l
/etc/pam.d/system-auth
/etc/pam.d/systemd-user
/etc/pam.d/vlock
/etc/pam.d/vmtoolsd
/etc/pam.d/xserver
/etc/rsyslog.conf
/etc/ssh
/etc/ssh/sshd_config
/var/log/audit
/var/log/audit/audit.log
/var/log/messages
/var/log/secure
EOF
#---------------------------------------------------------------------
cat << EOF >> /tmp/filematrix/filematrix.sh
#!/bin/bash
while read line
do
 getfacl -p \$line
done<"/tmp/filematrix/filematrix_rhel8.txt"
EOF
#---------------------------------------------------------------------
cat << EOF >> /tmp/filematrix/filecompare.sh
#!/bin/bash
ARGS=2
E_BADARGS=65
E_UNREADABLE=66
if [ \$# -ne "\$ARGS" ]
then
echo "Use Order: \`basename \$0\` file1 file2"
exit \$E_BADARGS
fi
if [[ ! -r "\$1" || ! -r "\$2" ]]
then
echo "Both files must be present and have read-right"
exit \$E_UNREADABLE
fi
cmp \$1 \$2 &> /dev/null
if [ \$? -eq 0 ]
then
echo "file_1 "\$1" identical to file_2 "\$2"."
else
echo "file_1 "\$1" differs from file_2 "\$2"."
#echo "Differences:"
#comm -3 --output-delimiter=file_2: \$1 \$2
fi
exit 0
EOF
#---------------------------------------------------------------------
#---------------------------------------------------------------------
cat << EOF >> /tmp/filematrix/filematrix_audit.sh
#!/bin/bash
mkdir -p /tmp/filematrix_audit && cd /tmp/filematrix_audit
/tmp/filematrix/filematrix.sh > filematrix_\`hostname\`.log && /tmp/filematrix/filecompare.sh /tmp/filematrix_standard_rhel8.log filematrix_\`hostname\`.log > filematrix_\`hostname\`_audit_status.log
diff -y /tmp/filematrix_standard_rhel8.log filematrix_\`hostname\`.log > filematrix_\`hostname\`_difference.log
EOF
#---------------------------------------------------------------------
chmod +x /tmp/filematrix/file*.sh
#---------------------------------------------------------------------

