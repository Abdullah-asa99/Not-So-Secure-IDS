import re
from suricataparser import parse_file
from scapy.all import IP,TCP,UDP,DNS,Raw
import logging

file = ""

def get_rule_content(rule):
    pattern = r'content:"(.*?)"'
    content = re.findall(pattern, rule.raw)
    return content


def analyze_pckt(packet):
    

    logging.basicConfig( level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',handlers = [logging.FileHandler('output.log'), logging.StreamHandler()])

    try:
        rule_list = parse_file(file)
        #rule_list = parse_file(".\suricata.rules")
    except:
        logging.error("Error parsing the rules file please provide correctly  formated file")
        exit(-1)

    for rule in rule_list:
        if rule is not None:
            try:
                #check dns qaueries
                detect_web(rule,packet)
                if packet[UDP].dport == 53: 
                    detect_dns(rule,packet)
            except:
                pass
        else:
            pass




def detect_dns(content,packet):
     if packet.haslayer(DNS):
        try:
            dns_query = packet[DNS].qd.qname.decode('utf-8')
            if dns_query[:-1] in content.msg :
                logging.critical(f"DNS query for {dns_query} detected from {packet[IP].src}")

        except:
            pass

def detect_web(rule,packet):
    if packet.haslayer(TCP):
        if packet[TCP].dport == 80 or packet[TCP].sport == 80: #only http requests
            try:
                http_request = packet[Raw].load
                content = get_rule_content(rule)
                for sig in content:
                    if sig in str(http_request):
                        #print(rule.msg)
                        logging.critical(f"{rule.msg}: {sig}")
            except:
                pass

def detect_port_scan():
    
    print()