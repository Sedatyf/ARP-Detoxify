from scapy.all import Ether, ARP, srp, send
import os, sys
import re
import termcolor

arp_table = {}
duplicate_address = ""
is_attacked = False

def am_i_poisoned(current_os):  # sourcery skip: remove-redundant-if

    global arp_table
    global duplicate_address
    global is_attacked

    if 'linux' in current_os:
        arp_file = "/proc/net/arp"
        with open(arp_file, 'r') as f:
            arp_table = f.read()

        regex_ip = r"\b[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}\b"
        regex_mac = "[a-fA-F,0-9]{2}:[a-fA-F,0-9]{2}:[a-fA-F,0-9]{2}:[a-fA-F,0-9]{2}:[a-fA-F,0-9]{2}:[a-fA-F,0-9]{2}"

        ip_address = re.findall(regex_ip, arp_table)
        mac_address = re.findall(regex_mac, arp_table)

    elif 'win' in current_os:
        ans_cmd = os.popen('cmd /c "arp -a"').read().split("\n")

        parsed_ans = []
        ip_address = []
        mac_address = []
        arp_table = {}

        for _, line in enumerate(ans_cmd):
            if line.find("dynamic") != -1 or line.find("dynamique") != -1:
                parsed_ans.append(line.split())

        for line in parsed_ans:
            ip_address.append(line[0])
            mac_address.append(line[1])

    arp_table = dict(zip(ip_address, mac_address))
    
    for element in mac_address:
        if mac_address.count(element) > 1:
            duplicate_address = element
            is_attacked = True

    if is_attacked:
        termcolor.cprint("[!] You're currently being attacked as we found the same MAC address {} twice!!".format(duplicate_address), "red")
    else:
        termcolor.cprint("[*] Everything seems fine!", "green")


def who_is_attacker(current_os):  # sourcery skip: last-if-guard, remove-pass-elif

    if "linux" in current_os:
        route_file = "/proc/net/route"
        with open(route_file, "r") as f:
            route_table = str(f.read())
        
        hex_ip = re.findall("[A-F0-9]{8}", route_table)
        
        if hex_ip[0] == "00000000":
            hex_ip_list = re.findall("[A-F0-9]{2}", hex_ip[1])[::-1]
        
        ip_list = [str(int(hexa, 16)) for hexa in hex_ip_list]
        gw_ip = ".".join(ip_list)
    
    elif "win" in current_os:
        dflt_gw = []

        ans_cmd = os.popen('cmd /c "ipconfig"').read().split("\n")

        for _, line in enumerate(ans_cmd):
            if line.startswith("   Default Gateway") or line.startswith("   Passerelle par défaut"):
                dflt_gw.append(line)
        
        regex_ip = r"\b[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}\b"
        for element in dflt_gw:
            if re.search(regex_ip, element) != None:
                temp_ip = re.findall(regex_ip, element)
                gw_ip = temp_ip[0]
    
    print(f"[*] Your gateway is {gw_ip}")
    for ip, mac in arp_table.items():
        if mac == duplicate_address and ip != gw_ip:
            termcolor.cprint(f"[!] Your attacker is {ip}", "red")

    
if __name__ == "__main__":
    current_os = sys.platform

    am_i_poisoned(current_os)
    
    if is_attacked:
        who_is_attacker(current_os)