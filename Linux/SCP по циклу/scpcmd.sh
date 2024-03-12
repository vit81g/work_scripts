#!/usr/bin/expect -f
#use scpcmd.sh filename target targetpath password
set filename [lindex $argv 0]
set target [lindex $argv 1]
set remotepath [lindex $argv 2]
set pass  [lindex $argv 3]
set timeout 10
spawn scp $filename rvision@$target:$remotepath
expect "yes/no" {
        exp_send "yes\r"
        exp_continue
    } "*?assword" {
        exp_send "$pass\r"
        exp_continue
    } eof
catch wait result
exit
