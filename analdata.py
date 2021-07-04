from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP
import binascii

def render_csv_row(ip_fields, tcp_fields, service, time, payload, payload_raw, payload_hex, fh_csv):

    chca = ""
    for i in range(len(ip_fields)):
        chca += str(ip_fields[i]) +' \t '

    chca1 = ""
    for i in range(len(tcp_fields)):
        chca1 += str(tcp_fields[i]) +' \t '

    #print((ip_fields))
    print(f'{chca}{service}\t{time}\t {chca1}{payload}\t {payload_raw}\t {payload_hex}', file=fh_csv)

    return True

def pcap2csv(in_pcap, out_csv):
    ip_fields = [field.name for field in IP().fields_desc]
    tcp_fields = [field.name for field in TCP().fields_desc]

    pcap = rdpcap(in_pcap)
    frame_num = 0
    ignored_packets = 0
    count = 0
    with open(out_csv, 'w') as fh_csv:
        for packet in pcap[IP]:
            # Field array for each row of DataFrame
            ip_field_values = []
            tcp_field_values = []
            # Add all IP fields to dataframe
            for field in ip_fields:
                if field == 'options':
                    # Retrieving number of options defined in IP Header
                    ip_field_values.append(len(packet[IP].fields[field]))
                else:
                    ip_field_values.append(packet[IP].fields[field])

            temp = packet.time

            layer_type = type(packet[IP].payload)
            for field in tcp_fields:
                try:
                    if field == 'options':
                        tcp_field_values.append(len(packet[layer_type].fields[field]))
                    else:
                        tcp_field_values.append(packet[layer_type].fields[field])
                except:
                    tcp_field_values.append(None)

            ip_packet = pcap[count][IP]
            segment = ip_packet.payload
            data = segment.payload
            data_sum = data.summary().split(' ')
            count += 1

            # Append payload
            payload = (len(packet[layer_type].payload))
            payload_raw = (packet[layer_type].payload.original)
            payload_hex = (binascii.hexlify(packet[layer_type].payload.original))

            try:
                frame_num += 1
                if not render_csv_row(ip_field_values, tcp_field_values, data_sum[0], temp, payload, payload_raw, payload_hex, fh_csv):
                    ignored_packets += 1
            except StopIteration:
                break

    print('{} packets read, {} packets not written to CSV'.format(frame_num, ignored_packets))

pcap ="fich.pcap"
csv = "fic1.csv"
pcap2csv(pcap, csv)