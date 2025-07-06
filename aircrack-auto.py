import subprocess
import time
import os
import re
from typing import List, Dict

def scan_networks(interface: str, scan_time: int = 10) -> List[Dict[str, str]]:
    try:
        output_file = "airodump_output"
        command = f"airodump-ng -w airodump_output --output-format csv {interface}"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
        print(f"Ошибка при сканировании сетей: {e}")
        return []

def check_network(network: list) -> bool:
    if not network["ESSID"]:
        return False
    if not network["Authentication"] == "PSK":
        print("[      AUTH is not PSK      ]", network["ESSID"])
        return False
    if not (network["Privacy"] == "WPA2" or network["Privacy"] == "WPA1"):
        print("[Unsupported encryption type]", network["ESSID"])
        return False
    
    output_file = "airodump_output"
    command = f"airodump-ng --bssid {network['BSSID']} -c {network['channel']} -w airodump_output --output-format csv {interface}"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(scan_time)
    
    process.terminate()
    try:
        process.wait(timeout=scan_time)
    except subprocess.TimeoutExpired:
        process.kill()
    
    with open(output_file + "-01.csv", "r") as file:
        lines = file.readlines()
    
    os.remove(output_file + "-01.csv")
    
    clients = []
    start_parsing = 0

    # Идём до начала списка клиентов
    for i, line in enumerate(lines[start_parsing:]):
        line = line.strip()
        if line.startswith("Station MAC,"):
           start_parsing += i + 1
           break

    # Идём до конца списка клиентов и парсим их
    for i, line in enumerate(lines[start_parsing:]):
        line = line.strip()
        if not line:
           start_parsing += i + 1
           break

        parts = re.split(r'\s*,\s*', line)
        if len(parts) >= 6:
            client = {
                "Station MAC": parts[0].strip(),
                "First_time_seen": parts[1].strip(),
                "Last_time_seen": parts[2].strip(),
                "Power": parts[3].strip(),
                "Packets": parts[4].strip(),
                "BSSID": parts[5].strip(),
                "Probed_ESSIDs": parts[6].strip() if len(parts) > 6 else ""
            }
            clients.append(client)
    if not len(clients):
        print("[    AP have not clients    ]", network["ESSID"])
        return False
    
    print("[      AP is vulnerable     ]", network["ESSID"])
    clients.sort(key=lambda d: int(d["Power"]), reverse=True)      
    network["clients"] = clients
    return True


def get_targets(networks: list, interface: str, scan_time: int = 5) -> List[Dict[str, str]]:
    print(f"Search for vulnerable networks:")
    targets = []
    for network in networks:
        if check_network(network):
            targets.append(network)
    return targets

def confirm(question: str, default = None) -> bool:
    if default == None:
        question = f"{question} [y/n]: "
    elif default:
        question = f"{question} [Y/n]: "
    else:
        question = f"{question} [y/N]: "
    while True:
        answer = input(question).capitalize()
        if answer == "Y":
            return True
        elif answer == "N":
            return False
        elif answer == "":
            if not default == None:
                return default

def attacks_menu(networks: list, interface: str):
    print(f"{len(networks)} networks selected")
    while True:
        print("Sellect attack type:")
        print("1. Handshake (Active)")
        print("0. Back")
        
        choice = input("> ").strip()
        if choice == "1":
            pass
        elif choice == "0":
           break
        else:
            print("Incorrect input!")

def main():
    INTERFACE = "wlan0mon"
    networks = scan_networks(INTERFACE, scan_time=1) 
    print(f"Found {len(networks)} networks")
    while True:
        print("1. Sellect Network")
        print("2. Sellect All Networks")
        print("0. Exit")

        choice = input("> ").strip()
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
    main()
