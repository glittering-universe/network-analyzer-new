# stats.py
from collections import defaultdict
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from PyQt5.QtWidgets import QWidget, QVBoxLayout
import time


class StatsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.stats = defaultdict(int)
        self.start_time = time.time()
        self.dns_timestamps = []
        self.dns_counts = []

        self.layout = QVBoxLayout()
        self.figure = plt.Figure(figsize=(12, 10), tight_layout=True)
        self.canvas = FigureCanvas(self.figure)
        self.layout.addWidget(self.canvas)
        self.setLayout(self.layout)

        # 创建多个子图
        self.ax_pie = self.figure.add_subplot(221)  # IPv4 vs IPv6
        self.ax_bar = self.figure.add_subplot(222)  # TCP, UDP, ARP
        self.ax_line = self.figure.add_subplot(212)  # DNS over time

    def update_stats(self, packet):
        if packet.haslayer('IP'):
            self.stats['IPv4'] += 1
        elif packet.haslayer('IPv6'):
            self.stats['IPv6'] += 1
        if packet.haslayer('TCP'):
            self.stats['TCP'] += 1
        if packet.haslayer('UDP'):
            self.stats['UDP'] += 1
        if packet.haslayer('ARP'):
            self.stats['ARP'] += 1
        if packet.haslayer('DNS'):
            self.stats['DNS'] += 1
            current_time = time.time() - self.start_time
            self.dns_timestamps.append(current_time)
            self.dns_counts.append(self.stats['DNS'])

    def render_pie_chart(self):
        self.ax_pie.clear()
        labels = ['IPv4', 'IPv6']
        sizes = [self.stats['IPv4'], self.stats['IPv6']]
        colors = ['skyblue', 'lightgreen']
        if sum(sizes) > 0:
            self.ax_pie.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140, colors=colors)
            self.ax_pie.set_title('IPv4 vs IPv6')
        self.ax_pie.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
        self.canvas.draw()

    def render_bar_chart(self):
        self.ax_bar.clear()
        labels = ['TCP', 'UDP', 'ARP']
        sizes = [self.stats['TCP'], self.stats['UDP'], self.stats['ARP']]
        colors = ['blue', 'green', 'red']
        self.ax_bar.bar(labels, sizes, color=colors)
        self.ax_bar.set_title('TCP, UDP, ARP Statistics')
        self.ax_bar.set_ylabel('数量')
        self.canvas.draw()

    def render_line_chart(self):
        self.ax_line.clear()
        if self.dns_timestamps:
            self.ax_line.plot(self.dns_timestamps, self.dns_counts, marker='o', linestyle='-', color='purple')
            self.ax_line.set_title('DNS Packet Count Over Time')
            self.ax_line.set_xlabel('Time (s)')
            self.ax_line.set_ylabel('DNS Count')
        self.canvas.draw()

    def update_visualization(self):
        self.render_pie_chart()
        self.render_bar_chart()
        self.render_line_chart()