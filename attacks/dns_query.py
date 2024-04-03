from scapy.all import IP,UDP,TCP,DNS,DNSQR,sr1

# Create DNS query packet
dns_query = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="evil.com", qtype="A"))

# Send DNS query packet and receive response
response = sr1(dns_query, verbose=0)

# Print response
if response and response.haslayer(DNS):
    print("DNS Response:")
    print(response.summary())
    print(response.show())
else:
    print("No response received.")