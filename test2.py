import argparse
import nmap
from pymetasploit3.msfrpc import MsfRpcClient
import openai
import xml.etree.ElementTree as ET

openai.api_key = "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"
model_engine = "text-davinci-003"
nm = nmap.PortScanner()

parser = argparse.ArgumentParser(description='Python-Nmap and chatGPT integrated Vulnerability scanner')
parser.add_argument('target', metavar='target', type=str, help='Target IP or hostname')
args = parser.parse_args()

target = args.target


class Scanner:

    def __init__(self):
        self.scan_profiles = {
            'p1': '-Pn -sV -T4 -O -F',
            'p2': '-Pn -T4 -A -v',
            'p3': '-Pn -sS -sU -T4 -A -v',
            'p4': '-Pn -p- -T4 -A -v',
            'p5': '-Pn -sS -sU -T4 -A -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script=vuln'
        }
        self.metasploit_host = 'localhost:'
        self.metasploit_port = 3790
        self.metasploit_user = 'admin '
        self.metasploit_pass = 'RX*;Y9oz'

    def scan(self, target, profile):
        if profile not in self.scan_profiles:
            return 'Invalid profile selected'

        nm.scan(target, arguments=self.scan_profiles[profile])
        xml_output = nm.get_nmap_last_output()
        root = ET.fromstring(xml_output)

        vulnerabilities = []
        for host in root.findall('host'):
            for port in host.findall('ports/port'):
                for script in port.findall('script'):
                    if script.get('id') == 'vulners':
                        vulns = script.findall('table/table')
                        for vuln in vulns:
                            cves = [e.text for e in vuln.findall('elem[@key="cve"]')]
                            description = vuln.find('elem[@key="description"]').text
                            vulnerabilities.append({'port': port.get('portid'), 'protocol': port.get('protocol'), 'cves': cves, 'description': description})

        # Using Metasploit to do a deeper investigation
        client = MsfRpcClient(self.metasploit_host, port=self.metasploit_port)
        console_id = client.consoles.console().cid
        client.consoles.console(console_id).write(f'use auxiliary/scanner/portscan/nmap\nset RHOSTS {target}\nrun\n')
        report = client.consoles.console(console_id).read()
        client.consoles.console(console_id).destroy()

        # Generate exploit or payload using GPT
        prompt = ''
        for vuln in vulnerabilities:
            prompt += f"Exploit or payload for CVEs {', '.join(vuln['cves'])}: {vuln['description']}\n"
        completion = openai.Completion.create(
            engine=model_engine,
            prompt=prompt,
            max_tokens=1024,
            n=1,
            stop=None,
            temperature=0.5
        )

        print(completion.choices[0].text)


if __name__ == '__main__':
    profile = input("Enter profile of scan (p1-p5): ")
    scanner = Scanner()
    scanner.scan(target, profile)
