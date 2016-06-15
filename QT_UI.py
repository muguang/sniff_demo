# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'design.ui'
#
# Created by: PyQt5 UI code generator 5.5.1
#
# WARNING! All changes made in this file will be lost!
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import *

from sniffer import My_sniffer, packages, sniff_thread
from scapy.utils import hexdump

import io
from contextlib import redirect_stdout
import time
import threading
dictBox = dict()



count = 1

# move from sniffer to QT

class Ui_MainWindow(object):

    def setupUi(self, MainWindow):
        MainWindow.setObjectName("Sniffer")
        MainWindow.resize(800, 718)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")

        self.listWidget = QtWidgets.QListWidget(self.centralwidget)
        self.listWidget.setGeometry(QtCore.QRect(120, 10, 661, 271))

        self.listWidget.setObjectName("listWidget")

        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(0, 20, 113, 32))
        self.pushButton.setObjectName("pushButton")

        self.pushButton2 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton2.setGeometry(QtCore.QRect(0, 40, 113, 32))
        self.pushButton2.setObjectName("pushButton")

        self.textBrowser = QtWidgets.QTextBrowser(self.centralwidget)
        self.textBrowser.setGeometry(QtCore.QRect(120, 460, 671, 192))
        self.textBrowser.setObjectName("textBrowser")

        # TODO : 还不熟悉 treeWidget 控件, 先使用textBrowser 显示数据
        # self.treeWidget = QtWidgets.QTreeWidget(self.centralwidget)
        # self.treeWidget.setGeometry(QtCore.QRect(120, 270, 651, 181))
        # self.treeWidget.setObjectName("treeWidget")
        # self.treeWidget.headerItem().setText(0, "1")

        self.textBrowser2 = QtWidgets.QTextBrowser(self.centralwidget)
        self.textBrowser2.setGeometry(QtCore.QRect(120, 280, 651, 181))
        self.textBrowser2.setObjectName("textBrowser2")






        self.listWidget_2 = QtWidgets.QListWidget(self.centralwidget)
        self.listWidget_2.setGeometry(QtCore.QRect(10, 70, 101, 591))
        self.listWidget_2.setObjectName("listWidget_2")

        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 800, 22))
        self.menubar.setObjectName("menubar")

        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.retranslateUi(MainWindow)
        self.pushButton.clicked.connect(self.show_flow)
        #self.pushButton2.clicked.connect(self.stop_sniff)
        # self.pushButton2.clicked.connect(self.start_sniff)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)


        # 当widget中选中的的item被改变时,触发 显示 hexdump和协议包的内容
        self.listWidget.doubleClicked.connect(self.click_show_info)
        self.listWidget.doubleClicked.connect(self.click_show_more_info)

        self.Sniff_thread = sniff_thread


    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.pushButton.setText(_translate("MainWindow", "Start_sniff"))
        self.pushButton2.setText(_translate("MainWIndow", "stop_sniff"))

    ## 将package中的内容传输到 dictBox中
    #TODO : 之后需要动态添加




    def click_show_more_info(self):
        # 在 textBrowser上显示各个协议的内容
        self.add_data_show()

    def add_data_show(self):
        with io.StringIO() as buf, redirect_stdout(buf):
            dictBox[self.listWidget.currentItem().text()].show()
            output = buf.getvalue()
        #
        # print("output of data : ", output)

        self.textBrowser2.clear()
        self.textBrowser2.setPlainText(output)
        self.textBrowser2.show()
        # pass

    def add_hexdump_data(self, dictBox):

        # hexdump_UI 显示的数据
        with io.StringIO() as buf, redirect_stdout(buf):

            # print("sonmgthing")
            try:
                temp = dictBox[self.listWidget.currentItem().text()]
                hexdump(temp)
            except:
                print(" hexdump error")
            output = buf.getvalue()

        # print(self.listWidget.currentIndex())
        # print(type(self.listWidget.currentIndex()))
        #
        # print("output : ", output)
        self.textBrowser.clear() # 清除历史
        self.textBrowser.setPlainText(output) #
        self.textBrowser.show()

    # 在textBrower上显示出hexdump的详细内容
    def click_show_info(self):

        self.add_hexdump_data(dictBox)

        # TODO: 点击列表的一条,然后 下面会显示 这个package的详细信息,包解析 ,hexdump()
        # self.listWidget.itemDoubleClicked.connect(self.add_hexdump_data(dictBox))
        # for i in range(self.listWidget.count()):
        #     print(i)


        # pass

    # 更新包
    def create_dict(self):
        # 检测是否抓到新包
        while True:
            ui_package = []
            for item in packages:
                ui_package.append(item)
            len_p = len(ui_package)
            len_d = len(dictBox)
            # print(len_p)
            # print("ui_package : ", ui_package)
            # print("----"*4)
            temp_list = ui_package[len_d-len_p:] # 将 package比listBox多的存到 temp_list中

            for item in temp_list:
                global count
                temp = str(count) +" "+ item.summary()
                dictBox[temp] = item
                self.listWidget.addItem(temp)
                count += 1
            print(self.listWidget.count())
            self.listWidget.show()
            self.show_statistic()
            time.sleep(1)



    # 对 listWidget 的排序
    def sort_list(self):
        for item in dictBox():
            pass


    def show_flow(self):
        # sniff 将结果保存到了packages
        # pack_call_back(packages)

        #开启了嗅探线程
        thread1 = threading.Thread(target=self.Sniff_thread)
        thread1.start()
        thread2 = threading.Thread(target=self.create_dict)
        thread2.start()


        #
        # self.listWidget.show()
        # self.show_statistic()



    def show_statistic(self):
        count_IP = 0
        count_IP_TCP = 0
        count_IP_UDP = 0
        count_ARP = 0
        count_IPv6 = 0
        count_IP_ICMP = 0

        for item in dictBox.keys():
            if "IPv6" in item:
                count_IPv6 += 1
            elif "TCP" in item:
                count_IP_TCP += 1
                count_IP += 1
            elif "UDP" in item:
                count_IP_UDP += 1
                count_IP += 1
            elif "ARP" in item:
                count_ARP += 1
            elif "ICMP" in item:
                count_IP_ICMP +=1
                count_IP += 1
            else:
                print("some other pack")
                print(item)
        # print("Ipv6 :", count_IPv6,
        #       "TCP :", count_IP_TCP,
        #       "UDP :", count_IP_UDP,
        #       "ARP : ", count_ARP,
        #       "IP : " , count_IP,
        #       )
        self.listWidget_2.clear()
        self.listWidget_2.addItem("IPv6 : %d " % count_IPv6)
        self.listWidget_2.addItem("TCP : %d" % count_IP_TCP)
        self.listWidget_2.addItem("UDP : %d" % count_IP_UDP)
        self.listWidget_2.addItem("ARP : %d" % count_ARP)
        self.listWidget_2.addItem("IP : %d" % count_IP)
        self.listWidget_2.addItem("ICMP : %d" % count_IP_ICMP)
        # self.listWidget_2.addItem("IPv6 : ", count_IPv6)
        self.listWidget_2.show()
