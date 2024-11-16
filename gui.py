# gui.py
from PyQt5.QtWidgets import (
    QMainWindow, QAction, QVBoxLayout, QWidget, QTableWidget,
    QTableWidgetItem, QLabel, QLineEdit, QPushButton, QHBoxLayout, QFileDialog, QMessageBox, QFrame
)
from PyQt5.QtCore import Qt, QTimer
from sniffer import PacketSniffer
from stats import StatsPanel
from resource_monitor import ResourceMonitor
from scapy.all import wrpcap, rdpcap
from collections import defaultdict


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Python Wireshark 仿制软件")
        self.setGeometry(100, 100, 1200, 800)

        # 菜单栏
        menubar = self.menuBar()
        file_menu = menubar.addMenu('文件')
        edit_menu = menubar.addMenu('编辑')

        # 菜单动作
        start_action = QAction('开始捕获', self)
        stop_action = QAction('停止捕获', self)
        save_action = QAction('保存数据', self)
        load_action = QAction('加载数据', self)
        clear_action = QAction('清屏', self)  # 新增清屏动作
        file_menu.addAction(start_action)
        file_menu.addAction(stop_action)
        file_menu.addAction(save_action)
        file_menu.addAction(load_action)
        file_menu.addAction(clear_action)  # 添加清屏到菜单

        # 主布局
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout()

        # 过滤器输入框和按钮
        filter_layout = QHBoxLayout()
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("输入过滤条件，例如 tcp, udp, ip")
        filter_button = QPushButton("应用过滤")
        filter_button.clicked.connect(self.apply_filter)
        filter_layout.addWidget(self.filter_input)
        filter_layout.addWidget(filter_button)
        main_layout.addLayout(filter_layout)

        # 数据包列表
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(['No.', '时间', '源地址', '目标地址', '协议'])
        self.table.horizontalHeader().setStretchLastSection(True)
        main_layout.addWidget(self.table)

        # 详细信息显示区域
        self.detail_frame = QFrame()
        self.detail_frame.setFrameShape(QFrame.StyledPanel)
        self.detail_frame.setVisible(False)  # 初始隐藏
        detail_layout = QVBoxLayout()
        self.detail_label = QLabel("选择一个数据包查看详细信息")
        self.detail_label.setAlignment(Qt.AlignTop)
        self.detail_label.setWordWrap(True)
        detail_layout.addWidget(self.detail_label)

        # 添加一个按钮来关闭详细信息
        close_detail_button = QPushButton("关闭详细信息")
        close_detail_button.clicked.connect(self.toggle_detail_view)
        detail_layout.addWidget(close_detail_button)
        self.detail_frame.setLayout(detail_layout)
        main_layout.addWidget(self.detail_frame)

        # 统计图表
        self.stats_panel = StatsPanel()
        main_layout.addWidget(self.stats_panel)

        # 资源监控
        self.resource_monitor = ResourceMonitor()
        main_layout.addWidget(self.resource_monitor)

        # 清屏按钮
        clear_button = QPushButton("一键清屏")
        clear_button.clicked.connect(self.clear_screen)
        main_layout.addWidget(clear_button)

        central_widget.setLayout(main_layout)

        # 初始化捕获器
        self.sniffer = PacketSniffer()
        self.sniffer.packet_captured.connect(self.add_packet)

        # 连接菜单动作
        start_action.triggered.connect(self.start_capture)
        stop_action.triggered.connect(self.stop_capture)
        save_action.triggered.connect(self.save_data_pcap)
        load_action.triggered.connect(self.load_data_pcap)
        clear_action.triggered.connect(self.clear_screen)  # 连接清屏动作

        # 连接表格选择事件
        self.table.itemSelectionChanged.connect(self.display_packet_details)

        # 定时器用于更新统计图表
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_statistics)
        self.stats_timer.start(1000)  # 每1秒更新一次统计

        self.packet_count = 0
        self.captured_packets = []

    def start_capture(self):
        self.sniffer.start_sniffing()
        print("开始捕获数据包")

    def stop_capture(self):
        self.sniffer.stop_sniffing()
        print("停止捕获数据包")

    def add_packet(self, packet):
        self.packet_count += 1
        self.captured_packets.append(packet)
        row_position = self.table.rowCount()
        self.table.insertRow(row_position)
        self.table.setItem(row_position, 0, QTableWidgetItem(str(self.packet_count)))
        self.table.setItem(row_position, 1, QTableWidgetItem(str(packet.time)))

        ip_layer = packet.getlayer('IP')
        if ip_layer:
            src = ip_layer.src
            dst = ip_layer.dst
        else:
            src = 'N/A'
            dst = 'N/A'
        self.table.setItem(row_position, 2, QTableWidgetItem(src))
        self.table.setItem(row_position, 3, QTableWidgetItem(dst))
        self.table.setItem(row_position, 4, QTableWidgetItem(packet.summary()))

        # 更新统计
        self.stats_panel.update_stats(packet)

    def display_packet_details(self):
        selected_items = self.table.selectedItems()
        if selected_items:
            row = selected_items[0].row()
            packet = self.captured_packets[row]
            details = packet.show(dump=True)
            self.detail_label.setText(f"<pre>{details}</pre>")
            self.detail_frame.setVisible(True)  # 显示详细信息
            self.detail_label.adjustSize()

    def toggle_detail_view(self):
        self.detail_frame.setVisible(False)

    def apply_filter(self):
        filter_text = self.filter_input.text()
        self.sniffer.stop_sniffing()
        self.sniffer.start_sniffing(filter=filter_text)
        print(f"应用过滤器: {filter_text}")

    def update_statistics(self):
        self.stats_panel.update_visualization()

    def save_data_pcap(self):
        filename, _ = QFileDialog.getSaveFileName(self, "保存数据包", "", "PCAP Files (*.pcap);;All Files (*)")
        if filename:
            wrpcap(filename, self.captured_packets)
            print(f"数据已保存到 {filename}")

    def load_data_pcap(self):
        filename, _ = QFileDialog.getOpenFileName(self, "加载数据包", "", "PCAP Files (*.pcap);;All Files (*)")
        if filename:
            try:
                packets = rdpcap(filename)
                self.table.setRowCount(0)
                self.captured_packets = []
                self.packet_count = 0
                self.stats_panel.stats = defaultdict(int)
                self.stats_panel.dns_timestamps = []
                self.stats_panel.dns_counts = []
                for packet in packets:
                    self.packet_count += 1
                    self.captured_packets.append(packet)
                    row_position = self.table.rowCount()
                    self.table.insertRow(row_position)
                    self.table.setItem(row_position, 0, QTableWidgetItem(str(self.packet_count)))
                    self.table.setItem(row_position, 1, QTableWidgetItem(str(packet.time)))

                    ip_layer = packet.getlayer('IP')
                    if ip_layer:
                        src = ip_layer.src
                        dst = ip_layer.dst
                    else:
                        src = 'N/A'
                        dst = 'N/A'

                    self.table.setItem(row_position, 2, QTableWidgetItem(src))
                    self.table.setItem(row_position, 3, QTableWidgetItem(dst))
                    self.table.setItem(row_position, 4, QTableWidgetItem(packet.summary()))

                    # 更新统计
                    self.stats_panel.update_stats(packet)
                print(f"数据已从 {filename} 加载")
            except Exception as e:
                print(f"加载数据失败: {e}")

    def clear_screen(self):
        confirm = QMessageBox.question(self, '确认清屏', '确定要清除所有捕获的数据和统计信息吗？',
                                       QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if confirm == QMessageBox.Yes:
            self.table.setRowCount(0)
            self.captured_packets = []
            self.packet_count = 0
            self.stats_panel.stats = defaultdict(int)
            self.stats_panel.dns_timestamps = []
            self.stats_panel.dns_counts = []
            self.stats_panel.update_visualization()
            self.detail_frame.setVisible(False)
            print("已清除所有捕获的数据和统计信息")

    def closeEvent(self, event):
        self.sniffer.stop_sniffing()
        event.accept()