import os, sys
import re

def check_if_duplicates(list_of_elements):
    if len(list_of_elements) == len(set(list_of_elements)):
        return False
    else:
        return True


def am_i_poisoned():

    current_os = sys.platform
    regex_ip = "[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}"
    regex_mac = "[a-fA-F,0-9]{2}:[a-fA-F,0-9]{2}:[a-fA-F,0-9]{2}:[a-fA-F,0-9]{2}:[a-fA-F,0-9]{2}:[a-fA-F,0-9]{2}"

    if 'linux' in current_os:
        arp_file = "/proc/net/arp"
        with open(arp_file, 'r') as f:
            arp_table = f.read()

        ip_address = re.findall(regex_ip, arp_table)
        mac_address = re.findall(regex_mac, arp_table)

    if 'win' in current_os:
        arp_table = []
        ans_cmd = os.popen('cmd /c "arp -a"').read().split("\n")

        for _, line in enumerate(ans_cmd):
            if 'dynamique' in line:
                arp_table.append(line)
        #WIP need to add ip and mac in list

    # Then check if in mac_address list there is a the same object
