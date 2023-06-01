#!/bin/sh

/etc/osmud/remove_ip_fw_rule.sh -i 192.168.7.169 -m b8:27:eb:9d:df:f1
echo $?
/etc/osmud/commit_ip_fw_rules.sh
echo $?

exit 0