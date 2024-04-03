from scapy.all import send,TCP,IP

# Craft an HTTP GET request
http_request = (
    b"GET /path/to/resource?param=(<![CDATA[<foo>]]>) HTTP/1.1\r\n"
    b"Host: www.example.com\r\n"
    b"User-Agent: Scapy\r\n"
    b"Accept: */*\r\n"
    b"\r\n"
)

# Send the HTTP request and receive the response
response = send(
    IP(dst="www.example.com") / TCP(dport=80) / http_request
)

