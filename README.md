# ARP-Detoxify
This script will check if you're being spoofed

It's actually checking ARP table. If there is two identical MAC addresses for two different IP addresses, 
then it will identify which IP is your gateway and which IP is your attacker.

This script was for learning purposes as it is easy to check if you're spoofed manually.

Since you can't do anything from the OS side to stop and/or prevent the attack, 
this script will only perform some scans. 

It's working on Linux and Windows. If you have your Windows in a language other than English or French it won't work as it's checking cmd's answers. 
