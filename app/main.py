# app/main.py
import sys
import sqlite3
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidget, QVBoxLayout, QWidget, QTableWidgetItem
from PyQt5.QtCore import QTimer

class NetWatchWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetWatch")
        self.setGeometry(100, 100, 800, 600)
        
        # Setup table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Time", "Device", "IP", "Site", "App"])
        
        # Layout
        layout = QVBoxLayout()
        layout.addWidget(self.table)
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)
        
        # Update table every 2 seconds
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_table)
        self.timer.start(2000)
        
        self.update_table()

    def update_table(self):
        conn = sqlite3.connect("db/netwatch.db")
        c = conn.cursor()
        c.execute("SELECT timestamp, device_name, ip, domain, app FROM activity ORDER BY timestamp DESC LIMIT 50")
        rows = c.fetchall()
        conn.close()
        
        self.table.setRowCount(len(rows))
        for row_idx, row_data in enumerate(rows):
            for col_idx, data in enumerate(row_data):
                self.table.setItem(row_idx, col_idx, QTableWidgetItem(str(data or "")))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetWatchWindow()
    window.show()
    sys.exit(app.exec_())
