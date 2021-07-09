import os
from scapy.all import *
import datetime
from apscheduler.schedulers.background import BackgroundScheduler

sched = BackgroundScheduler()
@sched.scheduled_job('interval', id='my_job_id', hours=2)
def sniffpac():
    date = datetime.datetime.now()
    file = "../../" + str(date.strftime("%B")) + "/" + str(date.year) + "-" + str(date.month) + "-" + str(date.day) + ".cap"
    os.system("cp fictest.pcap %s | 2>/dev/null"%file)
    cap = sniff(timeout=60)
    wrpcap("fictest.pcap", cap)

