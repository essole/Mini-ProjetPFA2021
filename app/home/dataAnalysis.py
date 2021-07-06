import pandas as pd
from datetime import datetime
from scapy.all import *
import numpy as np
from matplotlib.figure import Figure
import seaborn as sns
import matplotlib.pyplot as plt
from tabulate import tabulate

#from pandas.tools.plotting import scatter_matrix
# Create DataFrame
pd.set_option('display.max_columns', 700)
pd.set_option('display.max_rows', 400)
pd.set_option('display.min_rows', 10)
pd.set_option('display.expand_frame_repr', True)
df = pd.read_csv('fic1.csv', header=None, sep="\t", names=['version', 'ihl', 'tos', 'len', 'id', 'flags', 'frag', 'ttl', 'proto', 'chksum', 'src', 'dst', 'options', 'service', 'time', 'sport', 'dport', 'seq', 'ack', 'dataofs', 'reserved', 'tcp_flags', 'window', 'tcp_chksum', 'urgptr', 'tcp_options', 'payload', 'payload_raw', 'payload_hex'])

#often the time type isn't accurate so this line convert the time type into datatime
df['time'] = [datetime.fromtimestamp(float(date)) for date in df['time'].values]
df['time'] = pd.to_datetime(df.time, format='DD/MM/YY')
class datainfo:
    def __init__(self, df, nline=10):
        self.nline = nline
        self.df = df

    def showData(self):
        return (tabulate(self.df.head(self.nline), headers = 'keys', tablefmt = 'pretty'))

    def describeData(self):
        df_red = self.df.drop(['version', 'ihl', 'tos','len', 'id', 'flags', 'frag', 'ttl','chksum', 'options'], axis=1)
        return(df_red.describe())

    def infoData(self):
        return(self.df.info())

    def dataMedian(self):
        return(self.df.median())

# get the summary of the most curent value in the data
    def dataSummary(self):
        return(self.df.payload.mode())
# get a summary of the trafic
    def summ(self):
        return(self.df.mode())

#get the min and max size of the payloads being send in the network
    def minMaxpay(self):
        return(f"* La taille minimale des paquets envoyés dans le trafic est {self.df.payload.min()} \n * La taille maximale envoyée est {self.df.payload.max()}")

# get the min and max size of the payloads send by the top talktive IP
    def minMaxTIP(self):
        frequent_address = self.df['src'].describe()['top']
        pay = self.df[self.df['src'] == frequent_address]['payload']
        return(f"\n * La taille minimale des paquets envoyée par l'adresse IP le plus actif est {pay.min()} \n * La taille maximale envoyée est {pay.max()}")

#get info on the top talktive source address
    def frecSrcAd(self):
        return(self.df['src'].describe())

#get info on most targeted machine address
    def frecDstAd(self):
        return (self.df['dst'].describe())

    def respons_byte(self):
        src_address = self.df['src'].describe()['top']
        resp_payload = self.df[self.df['dst'] == src_address]['payload']
        data_new = self.df
        data_new['resp_payload'] = resp_payload
        return (data_new)

#address targed by the top talktive source address
    def frecComm(self):
        frequent_address = self.df['src'].describe()['top']
        dest = self.df[self.df['src'] == frequent_address]['dst'].unique()
        dport = self.df[self.df['src'] == frequent_address]['dport'].unique()
        return (f"Cette adresse source {frequent_address} cible le plus les machines d'adresse {dest} sur les ports TCP {dport}")

#detect the size of payload being sent by the top talktive src ip and the size of paylod given as response
    def avSizeTopIp(self):
        frequent_address = self.df['src'].describe()['top']
        avPayloadrcv = self.df[self.df['src'] == frequent_address]['payload'].mode()
        avPayloadresp = self.respons_byte()['resp_payload'].mode()
        return(f"\n * La taille des paquets envoyés par l'adresse IP communiquant le plus varie entre {avPayloadrcv} \n * Celle envoyée en réponses varie entre {avPayloadresp}")

#get the stats on the protocole being used in the trafic
    def statProto(self):
        proto = self.df.groupby(by='proto')
        return(proto.service.count())

#get the stats on the service being used in the trafic
    def statService(self):
        serv = self.df.groupby(by='service')
        return(serv.service.count())

# get the summary of the dataframe based on a specific service name eg http or dns ...
    def servSummary(self, servname):
        servsumm = self.df[self.df['service'].str.contains(servname)].describe()
        return(tabulate(servsumm, headers = 'keys', tablefmt = 'pretty'))

#visualize data by service
    def vizserv(self, servname):
        servsumm = self.df[self.df['service'].str.contains(servname)].head(self.nline)
        return(tabulate(servsumm, headers = 'keys', tablefmt = 'pretty'))

# detect a possible attack based on the service being by used the attacker and the size of bytes he/she is sending and recv
    def servAttack(self, serv):
        data = self.respons_byte()
        frequent_address = self.df['src'].describe()['top']
        servsrc = self.df[self.df['service'].str.contains(serv)].where(data['src']==frequent_address)
        servdst = data[data['service'].str.contains(serv)].where(data['dst']==frequent_address)
        servsumm = servdst['resp_payload']
        servsrc['resp_payload'] = servsumm
        return(tabulate(servsrc.describe(), headers = 'keys', tablefmt = 'pretty'))

#detect possible attack based on legimate service, using other port than the normalized one
    def portAttack(self, serv, port):
        frequent_address = self.frecSrcAd()['top']
        portser = df[df['service'].str.contains(serv)]
        porfrec = portser[portser['dst'] == frequent_address]
        portus = porfrec[porfrec['sport'] != port]
        return(portus)

#plot of the correlation matrix between services
    def corplot(self):
        sns.set(style="whitegrid")
        cmap = sns.diverging_palette(220, 10, as_cmap=True)
        f, ax = plt.subplots(figsize=(13, 13))
        servs = self.df.groupby(by='service')
        sns.heatmap(servs.corr(), cmap=cmap, annot=True)
        f.tight_layout()
        return(f)

# plot showing the statistic of data sent by every src address in the trafic
    def payplotsrc(self):
        source_addresses = self.df.groupby("src")['payload'].sum()
        f, ax = plt.subplots(figsize=(8, 8))
        source_addresses.plot(kind='barh', title="Addresses Sending bad Payloads in the Trafic", figsize=(8, 5))
        f.tight_layout()
        return(f)

# plot showing the statistic of data sent by most talkative dst address in the trafic
    def payplotdst(self):
        source_addresses = self.df.groupby("dst")['payload'].sum()
        f, ax = plt.subplots(figsize=(8, 8))
        source_addresses.plot(kind='barh', title="Addresses receiving the bad payloads or Targeted machines", figsize=(8, 5))
        f.tight_layout()
        return (f)

# plot to detect the time of the day when probable attacks are lunch
    def timeplot(self):
        frequent_address = self.frecSrcAd()['top']
        freq_add_df = df[df['src'] == frequent_address]
        x = freq_add_df['payload'].tolist()
        f, ax = plt.subplots(figsize=(15, 15))
        sns.barplot(x="time", y="payload", data=freq_add_df[['payload', 'time']],label="Total", color="b").set_title("History of bytes sent by most frequent address through time")
        f.tight_layout()
        return(f)

#plot that tend to seek a correlation between the attacks and time of the day
    def corplotbytime(self):
        sns.set(style="whitegrid")
        f= Figure(figsize=(8, 8))
        ax = f.subplots()
        #sns.pairplot(self.df, size=10, x_vars=["time"], y_vars=["payload"], ax=ax)
        self.df.plot(kind='scatter', x="time", y="payload",color=(0, 0, 0), colorbar=False, ax=ax)
        plt.grid(True)
        f.tight_layout()
        return(f)

obj = datainfo(df)
#var =df.groupby(by='proto')
obj.corplotbytime()
#print(obj.servSummary('DNS'))
#print(df['service'])
#print(df.time.head(10))
#plt.show()

#print(df.info())
#from IPython.display import display
#display(df)



