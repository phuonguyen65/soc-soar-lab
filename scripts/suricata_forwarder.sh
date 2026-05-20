#!/bin/bash
# suricata_forwarder.sh
# Script SCP copy Suricata EVE JSON log từ pfSense về Splunk VM
# Chạy mỗi phút bởi cron job
#
# Cron entry (user nvphuong):
# * * * * * /bin/bash /opt/splunk/bin/suricata_forwarder.sh
#
# Setup SSH key:
# ssh-keygen -t rsa -f /home/nvphuong/.ssh/pfsense_key
# ssh-copy-id -i /home/nvphuong/.ssh/pfsense_key.pub root@192.168.1.1

scp -i /home/nvphuong/.ssh/pfsense_key \
    root@192.168.1.1:/var/log/suricata/suricata_em064296/eve.json \
    /var/log/suricata_eve.json
