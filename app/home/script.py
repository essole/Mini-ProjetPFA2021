import os
def addrules(rule):
    rule_file = open('rule_file.txt', 'a')
    rule_file.write(rule)
    rule_file.close()
    os.system("cat rule_file.txt | sort | uniq > rule_file1.txt")
    os.system("sed -i '/^$/d' rule_file1.txt")
    return

def classifytrafic(file_csv):
    auth = open("auth_traf.csv", "a")
    bad = open("bad_traf.csv", "a")
    with open(file_csv,"r") as fs:
        var = fs.readlines()
    with open("rule_file1.txt") as rs:
         var2 = rs.readlines()
    for i in var:
        verf = ""
        for j in var2:
            var3 = j.rstrip('\n').split('|')
            no = 0
            for k in var3:
                if i.find(k) != -1:
                    no += 1
            if no == len(var3):
                verf +="  True"
            else:
                verf +="  False"
        if verf.find("True") != -1:
            auth.write(i)
        else:
            bad.write(i)
    auth.close()
    bad.close()
    os.system("cat auth_traf.csv | sort | uniq > auth_trafic.csv")
    os.system("cat bad_traf.csv | sort | uniq > bad_trafic.csv")
    return

