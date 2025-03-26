# app/main.py
import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel

class NetWatchWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetWatch")
        self.setGeometry(100, 100, 600, 400)  # x, y, width, height
        
        # Add a simple label
        label = QLabel("Welcome to NetWatch", self)
        label.move(250, 180)  # Center-ish position

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetWatchWindow()
    window.show()
    sys.exit(app.exec_())
