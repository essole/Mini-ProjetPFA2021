import matplotlib.pyplot as plt
import pandas as pd

pd.set_option('display.max_columns', 700)
pd.set_option('display.max_rows', 400)
pd.set_option('display.min_rows', 10)
pd.set_option('display.expand_frame_repr', True)
#df = pd.read_csv('app/home/fic1.csv', header=None, sep="\t", names=['version', 'ihl', 'tos', 'len', 'id', 'flags', 'frag', 'ttl', 'proto', 'chksum', 'src', 'dst', 'options', 'service', 'time', 'sport', 'dport', 'seq', 'ack', 'dataofs', 'reserved', 'tcp_flags', 'window', 'tcp_chksum', 'urgptr', 'tcp_options', 'payload', 'payload_raw', 'payload_hex'])


def Sta_Globale(df):
    Listes_des_protocoles0 = []
    Listes_des_protocoles0 = list(df['proto'])
    Listes_des_protocoles  = []
    for i in Listes_des_protocoles0:
        if i not in Listes_des_protocoles:
            Listes_des_protocoles.append(i)
    l = len(Listes_des_protocoles)
    x2 = [0] * l
    for i in range(0, l):
        x2[i] = Listes_des_protocoles0.count(Listes_des_protocoles[i])
    some = sum(x2)
    x3 = [0] * l
    for i in range(0, l):
        j = (x2[i] / some) * 100
        x3[i] = j
    f, ax = plt.subplots(figsize=(8, 8))
    plt.bar(Listes_des_protocoles, x3)
    plt.title("Percentage per protocol")
    plt.xlabel('Protocols')
    plt.ylabel('(%)')
    f.tight_layout()
    return(f)

def Sta_Globaleserv(df):
    Listes_des_protocoles0 = []
    Listes_des_protocoles0 = list(df['service'])
    Listes_des_protocoles = []
    for i in Listes_des_protocoles0:
        if i not in Listes_des_protocoles:
            Listes_des_protocoles.append(i)
    l = len(Listes_des_protocoles)
    x2 = [0] * l
    for i in range(0, l):
        x2[i] = Listes_des_protocoles0.count(Listes_des_protocoles[i])
    some = sum(x2)
    x3 = [0] * l
    for i in range(0, l):
        j = (x2[i] / some) * 100
        x3[i] = j
    g, ax = plt.subplots(figsize=(8, 8))
    plt.bar(Listes_des_protocoles, x3)
    plt.title("Percentage per service")
    plt.xlabel('Service')
    plt.ylabel('(%)')
    g.tight_layout()
    return (g)
