# main.py
import sys
from PyQt5.QtWidgets import QApplication
from gui import MainWindow
from utils import setup_logging

def main():
    setup_logging()
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()

    sys.exit(app.exec_())

if __name__ == '__main__':
    main()