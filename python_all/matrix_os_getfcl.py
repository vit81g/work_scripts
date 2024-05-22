import os

""" исходные данные """
os.system('touch resalt.txt')
# os.system('touch compare.txt')
result = open('result.txt', 'w')

catalog_files = ['/etc/audit',
                 '/etc/audit/auditd.conf',
                 '/etc/audit/audit.rules',
                 '/etc/sysconfig/auditd',
                 '/etc/audisp',
                 '/etc/audisp/plugins.d',
                 '/etc/audisp/plugins.d/syslog.conf',
                 '/etc/audit/rules.d',
                 '/etc/audit/rules.d/audit.rules',
                 '/etc/login.defs',
                 '/etc/login.defs',
                 '/etc/pam.d',
                 '/etc/rsyslog.conf',
                 '/etc/syslog-ng/',
                 '/etc/syslog-ng/syslog-ng.conf',
                 '/etc/ssh',
                 '/etc/ssh/sshd_config',
                 '/etc/ssh/sshd_config',
                 '/etc/ssh/sshd_config',
                 '/var/log/audit',
                 '/var/log/audit/audit.log',
                 '/var/log/messages',
                 '/var/log/secure',
                 '/var/log/auth.log',
                 ]

for i in catalog_files:
    cmd = "getfacl -p " + i
    n = os.popen(cmd, 'r')
    for m in n:
        result.write(m)

result.close()

# Доработать сравнение с эталоном
# compare
# read_file = open('resalt.txt', 'r')
# compare = open('compare.txt', 'w')

# lines = read_file.readlines()

# for line in lines:
#    for var1 in catalog_files:
#        if var1 in line:
#            if
# compare.write(var1)
# compare.close()









