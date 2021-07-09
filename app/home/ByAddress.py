import matplotlib.pyplot as plt
import pandas as pd

pd.set_option('display.max_columns', 700)
pd.set_option('display.max_rows', 400)
pd.set_option('display.min_rows', 10)
pd.set_option('display.expand_frame_repr', True)

def Stat_Address(df):
    Adresses = df['src']
    Add0 = list(Adresses)
    Add = []
    for i in Add0:
        if i not in Add:
            Add.append(i)
    return("La liste des adresses detectees dans ce traffic est: ", Add )

    # On donne la main a l'utilisateur pour saisir l<adresse
def plotbyadd(df,Adress):
    # Preparer les datasets des protocoles pour l'adresse choisie par l'utilisateur
    A = df[df.Source == Adress]
    Listes_des_protocoles0 = []
    Listes_des_protocoles0 = list(A['proto'])
    Listes_des_protocoles = []
    # Preparer la liste qui va contenir les protocoles qu'on a collcte du dataset
    for i in Listes_des_protocoles0:
        if i not in Listes_des_protocoles:
            Listes_des_protocoles.append(i)
    l = len(Listes_des_protocoles)
    x2 = [0] * l
    # Calculer le nombre de paquets dans le traffic pour chaque protocole
    for i in range(0, l):
        x2[i] = Listes_des_protocoles0.count(Listes_des_protocoles[i])
    ############################################################
    some = sum(x2)
    # Liste qui va contenir le pourcentage de chaque protocole
    x3 = [0] * l
    for i in range(0, l):
        j = (x2[i] / some) * 100
        x3[i] = j
    f, ax = plt.subplots(figsize=(8, 8))
    plt.bar(Listes_des_protocoles, x3)
    plt.title("Percentage per protocol of the IP address " + Adress)
    plt.xlabel('Protocols')
    plt.ylabel('(%)')
    f.tight_layout()
    return(f)

def plotbyserv(df,Adress):
    df_r = df[df.Source == Adress]
    # Preparer les datasets des protocoles pour l'adresse choisie par l'utilisateur
    A = df[df.Source == Adress]
    Listes_des_protocoles0 = []
    Listes_des_protocoles0 = list(A['service'])
    Listes_des_protocoles = []
    # Preparer la liste qui va contenir les protocoles qu'on a collcte du dataset
    for i in Listes_des_protocoles0:
        if i not in Listes_des_protocoles:
            Listes_des_protocoles.append(i)
    l = len(Listes_des_protocoles)
    x2 = [0] * l
    # Calculer le nombre de paquets dans le traffic pour chaque protocole
    for i in range(0, l):
        x2[i] = Listes_des_protocoles0.count(Listes_des_protocoles[i])
    ############################################################
    some = sum(x2)
    # Liste qui va contenir le pourcentage de chaque protocole
    x3 = [0] * l
    for i in range(0, l):
        j = (x2[i] / some) * 100
        x3[i] = j
    fig, ax = plt.subplots(figsize=(8, 8))
    plt.bar(Listes_des_protocoles, x3)
    plt.title("Percentage per service of the IP address " + Adress)
    plt.xlabel('service')
    plt.ylabel('(%)')
    fig.tight_layout()
    return (fig)
