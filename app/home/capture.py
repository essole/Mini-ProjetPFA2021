
from scapy.all import *
import datetime

def sniffpac():
    date = datetime.datetime.now()
    cap = sniff(timeout=15)
    wrpcap("fictest.pcap", cap)

#df= pd.read_csv('fic1.csv',sep="|", header=None,names=['num','time','high_proto','proto','desc','src_ip','sport','dst_ip','dport','length','payload'])


sniffpac()