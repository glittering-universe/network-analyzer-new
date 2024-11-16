# resource_monitor.py
import psutil
from PyQt5.QtCore import QTimer
from PyQt5.QtWidgets import QLabel, QHBoxLayout, QWidget
from utils import format_time, setup_logging
import time
import logging


class ResourceMonitor(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        setup_logging()
        self.start_time = time.time()

        self.layout = QHBoxLayout()
        self.cpu_label = QLabel("CPU: 0%")
        self.mem_label = QLabel("内存: 0%")
        self.time_label = QLabel("运行时间: 00:00:00")
        self.layout.addWidget(self.cpu_label)
        self.layout.addWidget(self.mem_label)
        self.layout.addWidget(self.time_label)
        self.setLayout(self.layout)

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_resources)
        self.timer.start(1000)  # 每秒更新一次

    def update_resources(self):
        cpu = psutil.cpu_percent()
        mem = psutil.virtual_memory().percent
        elapsed = time.time() - self.start_time
        formatted_time = format_time(elapsed)

        self.cpu_label.setText(f"CPU: {cpu}%")
        self.mem_label.setText(f"内存: {mem}%")
        self.time_label.setText(f"运行时间: {formatted_time}")

        # 记录到日志
        logging.info(f"CPU: {cpu}%, 内存: {mem}%")