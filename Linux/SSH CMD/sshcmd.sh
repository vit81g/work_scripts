#!/usr/bin/expect
#Usage sshcmd.sh <host> <ssh user> <ssh password> <cmd>
set timeout 60
spawn ssh [lindex $argv 1]@[lindex $argv 0]
expect "yes/no" {.
    send "yes\r"
    expect "*?assword" { send "[lindex $argv 2]\r" }
    } "*?assword" { send "[lindex $argv 2]\r" }

expect {
        "\$ " { send "[lindex $argv 3]\r" }
        "\> " { send "[lindex $argv 3]\r" }
}

expect {
        "\$ " { send "exit\r" }
        "\> " { send "exit\r" }
}
interact
