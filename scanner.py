#!/usr/bin/python3
import scapy
from threading import Thread

class scanner(Thread):
    """
    Listens to network traffic,
    and finds hosts on the network
    """
    def __init__(self):
        self.observers = []
        self.hostsFound = []

    def __alertObservers(self, message):
        """Call the update message on all observers"""
        for observer in self.observers:
            observer.update(message)

    def addObserver(self, observer):
        self.observers.add(observer)

    def getHosts(self):
        return self.hostsFound

    def run(self):
        """
        Run the actual scanner
        """
        pass

