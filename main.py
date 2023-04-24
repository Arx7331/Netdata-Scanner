# Netdata Shcanner by Arx
import ipaddress
import requests
import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

filename = input("Enter file that contains list of ranges: ")
outputfile = input("Output: ")
port = 19999
freads = 255

def format_ram(bytes):
    gb = bytes / (1024 ** 3)
    return f"{gb:.2f} GB"

def shcan(ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    result = s.connect_ex((str(ip), port))
    s.close()
    if result == 0:
        try:
            url = f"http://{str(ip)}:{port}/api/v1/info"
            makereq = requests.get(url)
            jsonresp = makereq.json()
            cpucores = (jsonresp['cores_total'])
            cpufreq = int((jsonresp['cpu_freq'])) / 1000000000
            osname = (jsonresp['os_name'])
            osver = (jsonresp['os_version_id'])
            virt = (jsonresp['virtualization'])
            ramtotal = int((jsonresp['ram_total']))
            ramtotal = format_ram(ramtotal)
        except json.decoder.JSONDecodeError:
            return None
        response = requests.get(url)
        if response.status_code == 200:
            resp = requests.get(f"https://ipwhois.app/json/{str(ip)}")
            dats = json.loads(resp.content.decode('utf-8'))
            asn = dats['asn']
            country = dats['country_code']
            isp = dats['isp']
            with open(outputfile, 'a') as f:
                f.write(f"""
                ======
                http://{str(ip)}:19999 
                Server Info >
                Cores: {cpucores} @ {cpufreq} GHz
                RAM : {ramtotal}
                OS: {osname} {osver} {virt}
                Network Info > 
                ASN: {asn} {isp} - Country: {country}
                ====
                """)
            return f"{str(ip)} - ASN: {asn}, Country: {country}"

#Create a list of IPS to scan from the ranges given
ips = []
with open(filename, 'r') as f:
    for line in f:
        line = line.strip()
        if '/' in line:
            ips.extend(str(ip) for ip in ipaddress.IPv4Network(line))
        else:
            ips.append(line)

results = []
with ThreadPoolExecutor(max_workers=freads) as executor:
    futures = [executor.submit(shcan, ip) for ip in ips]
    for future in as_completed(futures):
        result = future.result()
        if result is not None:
            results.append(result)

for result in results:
    print(result)
