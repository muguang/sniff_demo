#coding:utf-8

__auther = "JH"

from scapy.all import *

import time
import threading

#TODO : 设备网卡列表
#TODO :  多线程
#TODO  : 格式化显示

packages = list()



def pack_call_back(package):
    global packages
    # print(package)
    packages.append(package)
    print("on the pack_call_back : len %d of packages" % len(packages))



class My_sniffer(threading.Thread):

    def __init__(self, iface="en0", prn=None, filter=None, promisc=1, count=0):
        threading.Thread.__init__(self)

        self.iface = iface
        self.filter = filter
        self.promisc = promisc
        self.prn = prn
        self.count = count


    def start_sniff(self):
        # print(self.iface, self.prn, self.filter, self.count)
        sniff(iface=self.iface, prn=self.prn, filter=self.filter, count=self.count)

def sniff_thread():

    # my_sniffer = My_sniffer(prn=pack_call_back, count=10)
    my_sniffer = My_sniffer(prn=pack_call_back)
    my_sniffer.start_sniff()

# a = threading.Thread(target=sniff_thread())

if __name__ == '__main__':
    # sniff_thread()
    pass