#!/usr/bin/python3
import scapy.all
from threading import Thread

class Scanner(Thread):
    """
    Listens to network traffic,
    and finds hosts on the network
    """
    def __init__(self):
        Thread.__init__(self)
        self.observers = []
        self.hostsFound = []

    def __alertObservers(self, message):
        """
        Call the update message on all observers
        """
        for observer in self.observers:
            observer.update(message)

    def addObserver(self, observer):
        self.observers.append(observer)

    def getHosts(self):
        return self.hostsFound

    def addHost(self, ip):
        if ip not in self.hostsFound:
            self.hostsFound.append(ip)
            self.__alertObservers(ip)

    def run(self):
        """
        Run the actual scanner
        """
        def handler(packet):
            if "IP" in packet:
                for host in packet["IP"].src, packet["IP"].dst:
                    self.addHost(host)

        scapy.all.sniff(prn=handler)

if __name__ == "__main__":
    class Observer:
        def update(self, message):
            print(message)

    scanner = Scanner()
    scanner.addObserver(Observer())
    scanner.start()
