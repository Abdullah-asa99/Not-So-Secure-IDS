import argparse
from scapy.all import IP,TCP, sniff
import analyze
import logging


# logger to print on screen and save to log file
logging.basicConfig( level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',handlers = [logging.FileHandler('output.log'), logging.StreamHandler()])

parser = argparse.ArgumentParser(description='Not So Secure IDS.')

parser.add_argument('-i','--interface', type=str, help='Interface to listen on.The default is listen on all interfaces (eg. -i WiFi)')
parser.add_argument('-f','--file', type=str, help='The path to a file contains the rules.')


args = parser.parse_args()


if args.file is None:
    logging.error("Please provide file to read rules from using -f or use -h to see full help")
    exit(-1)

global file # set the file to read rules from
analyze.file = args.file

# read packets and send them to analyze.analyze_pckt for detection
if args.interface is not None:
    logging.info("Listening on interface: %s",args.interface)
    
    sniff( prn=analyze.analyze_pckt,count=-1,iface=args.interface, store=0) #remove count to read all traffic

else:
    sniff( prn=analyze.analyze_pckt,count=-1,  store=0) #remove count to read all traffic

