# sniffer.py
from scapy.all import sniff
from threading import Thread
from PyQt5.QtCore import pyqtSignal, QObject


class PacketSniffer(QObject):
    packet_captured = pyqtSignal(object)

    def __init__(self):
        super().__init__()
        self.sniffing = False

    def start_sniffing(self, interface=None, filter=None):
        self.sniffing = True
        Thread(target=self.sniff, args=(interface, filter), daemon=True).start()

    def sniff(self, interface, filter):
        sniff(
            iface=interface,
            filter=filter,
            prn=self.process_packet,
            stop_filter=lambda x: not self.sniffing
        )

    def process_packet(self, packet):
        self.packet_captured.emit(packet)

    def stop_sniffing(self):
        self.sniffing = False