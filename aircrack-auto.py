#!/usr/bin/env python3
import subprocess
import time
import sys
import os
import re
from typing import List, Dict
from cli import confirm
from attacks import dos, handshake_active

def scan_networks(interface: str, scan_time: int = 10) -> List[Dict[str, str]]:
    try:
        output_file = "airodump_output"
        command = f"airodump-ng -w {output_file} --output-format csv {interface}"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
        print(f"Scanning networks for {scan_time} seconds...")
        time.sleep(scan_time)
        
        process.terminate()
        try:
            process.wait(timeout=scan_time)
        except subprocess.TimeoutExpired:
            process.kill()
        
        with open(output_file + "-01.csv", "r") as file:
            lines = file.readlines()
        
        os.remove(output_file + "-01.csv")
        
        networks = []
        start_parsing = 0

        # Идём до начала списка сетей
        for i, line in enumerate(lines[start_parsing:]):
            line = line.strip()
            if line.startswith("BSSID,"):
               start_parsing += i + 1
               break

        # Идём до конца списка сетей и парсим их
        for i, line in enumerate(lines[start_parsing:]):
            line = line.strip()
            if not line:
               start_parsing += i + 1
               break

            parts = re.split(r'\s*,\s*', line)
            if len(parts) >= 14:
                network = {
                    "BSSID": parts[0].strip(),
                    "First_time_seen": parts[1].strip(),
                    "Last_time_seen": parts[2].strip(),
                    "channel": parts[3].strip(),
                    "Speed": parts[4].strip(),
                    "Privacy": parts[5].strip(),
                    "Cipher": parts[6].strip(),
                    "Authentication": parts[7].strip(),
                    "Power": parts[8].strip(),
                    "beacons": parts[9].strip(),
                    "IV": parts[10].strip(),
                    "LAN_IP": parts[11].strip(),
                    "ID_length": parts[12].strip(),
                    "ESSID": parts[13].strip(),
                }
                networks.append(network)  

        networks.sort(key=lambda d: int(d["Power"]), reverse=True)      

        return networks
    
    except Exception as e:
        print(f"Networks scan error: {e}")
        return []
def attacks_menu(networks: list, interface: str):
    print(f"{len(networks)} networks selected")
    while True:
        print("Sellect attack type:")
        print("1. Handshake (Active)")
        print("2. DOS")
        print("0. Back")
        
        try:
            choice = input("> ").strip()
        except EOFError:
            exit()
        if choice == "1":
            handshake_active(networks, interface)
        if choice == "2":
            attack_time = int(input("Enter attack time (0 to infinity): "))
            dos(networks, interface, attack_time)
        elif choice == "0":
           break
        else:
            print("Incorrect input!")

def main(INTERFACE):
    os.system("rm -f *.cap")
    os.system("rm -f *.csv")
    
    scan_time = int(input("Enter networks scanning duration: "))
    networks = scan_networks(INTERFACE, scan_time) 
    print(f"Found {len(networks)} networks")
    while True:
        print("1. Sellect Network")
        print("2. Sellect All Networks")
        print("0. Exit")

        try:
            choice = input("> ").strip()
        except EOFError:
            exit()
        if choice == "1":
            for i, network in enumerate(networks, 1):
                print(f"{i}. {network['ESSID']}")
            network_numbers = input("Enter network numbers separated by spaces: ").split()
            sellected_networks = []
            print("Sellected Networks:")
            for number in network_numbers:
                print(networks[int(number) - 1]["ESSID"])
                sellected_networks.append(networks[int(number) - 1])
            if not confirm("It's correct?", True):
                continue
            attacks_menu(sellected_networks, INTERFACE)
        elif choice == "2":
            attacks_menu(networks, INTERFACE)
        elif choice == "0":
            break
        else:
            print("Incorrect input!")

if __name__ == "__main__":
    if len(sys.argv) > 2:
        print("Too many arguments.")
        print(f"Usage: {sys.argv[0]} <INTERFACE>")
        exit()
    if len(sys.argv) > 1:
        INTERFACE = sys.argv[1]
    else:
        INTERFACE = "wlan0mon"
    main(INTERFACE)
