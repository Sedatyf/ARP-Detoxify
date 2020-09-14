import os, sys
import re
import termcolor

def am_i_poisoned():

    current_os = sys.platform

    if 'linux' in current_os:
        arp_file = "/proc/net/arp"
        with open(arp_file, 'r') as f:
            arp_table = f.read()

        regex_ip = "[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}"
        regex_mac = "[a-fA-F,0-9]{2}:[a-fA-F,0-9]{2}:[a-fA-F,0-9]{2}:[a-fA-F,0-9]{2}:[a-fA-F,0-9]{2}:[a-fA-F,0-9]{2}"

        ip_address = re.findall(regex_ip, arp_table)
        mac_address = re.findall(regex_mac, arp_table)

    if 'win' in current_os:
        ans_cmd = os.popen('cmd /c "arp -a"').read().split("\n")

        parsed_ans = []
        ip_address = []
        mac_address = []
        arp_table = {}

        for _, line in enumerate(ans_cmd):
            if 'dynamique' or 'dynamic' in line:
                parsed_ans.append(line.split())

        for line in parsed_ans:
            ip_address.append(line[0])
            mac_address.append(line[1])

        arp_table = dict(zip(mac_address, ip_address))
    
    is_attacked = False
    for element in mac_address:
        if mac_address.count(element) > 1:
            duplicate_address = element
            is_attacked = True

    if is_attacked:
        termcolor.cprint("[!] You're currently being attacked as we found the same MAC address {} twice!!".format(duplicate_address), "red")
    else:
        termcolor.cprint("[*] Everything seems fine!", "green")

if __name__ == "__main__":
    am_i_poisoned()
