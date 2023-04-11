import nmap
import openai
import argparse

openai.api_key = "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"
model_engine = "text-davinci-003"
nm = nmap.PortScanner()

parser = argparse.ArgumentParser(description='Python-Nmap and chatGPT intigrated Vulnerability scanner')
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
            'p5': '-Pn -sS -sU -T4 -A -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script=vuln',
            'p6': '-Pn --script http-apache-negotiation,c,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-php-version,http-robots.txt,http-shellshock,http-sitemap-generator,http-svn-enum,http-trace,http-userdir-enum,http-vuln-cve2015-1635,http-vuln-cve2017-5638,http-vuln-cve2017-8917,http-vuln-cve201',
            'p7': '-Pn -sU -T4  -p 53,69,111,123,137,138,161,162,445,500,514,520,623,626,1900,4500 --script broadcast-dhcp-discover,broadcast-dhcp6-discover,dns-service-discovery,snmp-info,snmp-sysdescr -vvv',
            'p8': '-Pn  --script banner -p 21,22,23,25,53,80,110,111,135,139,143,389,443,445,465,514,587,636,993,995,1025,1433,1521,2049,3306,3389,5900,5985,6000,6667,8000,8080,8443,8888,9100,9200,10000,49152,49153,49154,49155,49156,49157 -vvv',
            'p9': '-Pn -O -sS -sV -Pn -T4 --max-os-tries 2 --max-retries 1 --min-rtt-timeout 100ms --initial-rtt-timeout 500ms --max-rtt-timeout 3s --open -p 1-65535 -vvv',
            'p10': '-Pn --script=vuln,-Pn -O -sS -sV -Pn -T4 --max-os-tries 2 --max-retries 1 --min-rtt-timeout 100ms --initial-rtt-timeout 500ms --max-rtt-timeout 3s --open -p 1-65535 -vvv'
        }

    def scan(self, target, profile):
        if profile not in self.scan_profiles:
            return 'Invalid profile selected'

        nm.scan(target, arguments=self.scan_profiles[profile])
        json_data = nm.analyse_nmap_xml_scan()
        analyze = json_data["scan"]

        # Prompt about what the query is all about
        prompt = f"Do a vulnerability analysis of {analyze} and return a vulnerability report in JSON  If a vulnerability is detected, you can then research the vulnerability to determine if there is a known exploit that can be used"

        # A structure for the request
        completion = openai.Completion.create(
            engine=model_engine,
            prompt=prompt,
            max_tokens=1024,
            n=1,
            stop=None,
        )

        response = completion.choices[0].text
        return response


def main(target):
    scanner = Scanner()
    profile = input("Enter profile of scan (p1-p10): ")
    result = scanner.scan(target, profile)
    print(result)


if __name__ == "__main__":
    main(target)