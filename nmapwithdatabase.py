import sys
import subprocess
import json
import sqlite3
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, 
    QTextEdit, QFileDialog, QDateTimeEdit, QMessageBox, QListWidget, 
    QComboBox, QFormLayout, QTabWidget
)
from PyQt5.QtCore import QDateTime, QTimer
import csv

class NmapApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Nmap GUI')
        self.setGeometry(100, 100, 800, 600)

        self.layout = QVBoxLayout()
        self.tabs = QTabWidget()
        self.layout.addWidget(self.tabs)

        self.create_scan_config_tab()
        self.create_schedule_scan_tab()
        self.create_results_tab()
        self.create_history_tab()

        self.setLayout(self.layout)

        self.scheduled_scans = []
        self.process = None
        self.timer = QTimer()
        self.timer.timeout.connect(self.run_scheduled_scans)
        self.timer.start(1000)

        self.init_db()
        self.load_scan_history()

    def init_db(self):
        self.conn = sqlite3.connect('scan_history.db')
        self.cursor = self.conn.cursor()
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY,
                name TEXT,
                target TEXT,
                scan_type TEXT,
                port_range TEXT,
                custom_args TEXT,
                nse_scripts TEXT,
                result TEXT
            )
        ''')
        self.conn.commit()

    def load_scan_history(self):
        self.history_list.clear()
        self.cursor.execute('SELECT id, target, name, scan_type FROM scans')
        rows = self.cursor.fetchall()
        for row in rows:
            self.history_list.addItem(f"{row[1]} - {row[2]} - {row[3]}")

    def create_scan_config_tab(self):
        scan_config_tab = QWidget()
        scan_config_layout = QFormLayout()

        self.scan_name_entry = QLineEdit()
        scan_config_layout.addRow('Scan Name:', self.scan_name_entry)

        self.target_entry = QLineEdit()
        scan_config_layout.addRow('Target:', self.target_entry)

        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(['TCP Scan', 'UDP Scan', 'SYN Scan', 'Ping Scan', 'OS Detection', 
                                       'ACK Scan', 'FIN Scan', 'Xmas Scan', 'NULL Scan', 'Window Scan'])
        scan_config_layout.addRow('Scan Type:', self.scan_type_combo)

        self.port_range_entry = QLineEdit()
        scan_config_layout.addRow('Port Range:', self.port_range_entry)

        self.custom_args_entry = QLineEdit()
        scan_config_layout.addRow('Custom Arguments:', self.custom_args_entry)

        self.nse_scripts_entry = QLineEdit()
        scan_config_layout.addRow('NSE Scripts:', self.nse_scripts_entry)

        run_button = QPushButton('Run Scan')
        run_button.clicked.connect(self.run_scan)
        scan_config_layout.addRow(run_button)

        stop_button = QPushButton('Stop Scan')
        stop_button.clicked.connect(self.stop_scan)
        scan_config_layout.addRow(stop_button)

        save_config_button = QPushButton('Save Config')
        save_config_button.clicked.connect(self.save_config)
        scan_config_layout.addRow(save_config_button)

        save_csv_button = QPushButton('Save Results to CSV')
        save_csv_button.clicked.connect(self.save_results_to_csv)
        scan_config_layout.addRow(save_csv_button)

        scan_config_tab.setLayout(scan_config_layout)
        self.tabs.addTab(scan_config_tab, "Scan Configuration")

    def create_schedule_scan_tab(self):
        schedule_tab = QWidget()
        schedule_layout = QFormLayout()

        self.schedule_name_entry = QLineEdit()
        schedule_layout.addRow('Scan Name:', self.schedule_name_entry)

        self.schedule_target_entry = QLineEdit()
        schedule_layout.addRow('Target:', self.schedule_target_entry)

        self.schedule_scan_type_combo = QComboBox()
        self.schedule_scan_type_combo.addItems(['TCP Scan', 'UDP Scan', 'SYN Scan', 'Ping Scan', 'OS Detection', 
                                                'ACK Scan', 'FIN Scan', 'Xmas Scan', 'NULL Scan', 'Window Scan'])
        schedule_layout.addRow('Scan Type:', self.schedule_scan_type_combo)

        self.schedule_port_range_entry = QLineEdit()
        schedule_layout.addRow('Port Range:', self.schedule_port_range_entry)

        self.schedule_custom_args_entry = QLineEdit()
        schedule_layout.addRow('Custom Arguments:', self.schedule_custom_args_entry)

        self.schedule_nse_scripts_entry = QLineEdit()
        schedule_layout.addRow('NSE Scripts:', self.schedule_nse_scripts_entry)

        self.datetime_edit = QDateTimeEdit(QDateTime.currentDateTime())
        self.datetime_edit.setCalendarPopup(True)
        schedule_layout.addRow('Schedule Time:', self.datetime_edit)

        schedule_button = QPushButton('Schedule Scan')
        schedule_button.clicked.connect(self.schedule_scan)
        schedule_layout.addRow(schedule_button)

        schedule_tab.setLayout(schedule_layout)
        self.tabs.addTab(schedule_tab, "Schedule Scan")

    def create_results_tab(self):
        results_tab = QWidget()
        results_layout = QVBoxLayout()

        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        results_layout.addWidget(self.results_text)

        results_tab.setLayout(results_layout)
        self.tabs.addTab(results_tab, "Scan Results")

    def create_history_tab(self):
        history_tab = QWidget()
        history_layout = QVBoxLayout()

        self.history_list = QListWidget()
        self.history_list.itemDoubleClicked.connect(self.load_scan_from_history)
        history_layout.addWidget(self.history_list)

        delete_history_button = QPushButton('Delete Selected History')
        delete_history_button.clicked.connect(self.delete_selected_history)
        history_layout.addWidget(delete_history_button)

        save_history_button = QPushButton('Save Scan History')
        save_history_button.clicked.connect(self.save_scan_history)
        history_layout.addWidget(save_history_button)

        refresh_button = QPushButton('Refresh History')
        refresh_button.clicked.connect(self.load_scan_history)
        history_layout.addWidget(refresh_button)

        import_history_button = QPushButton('Import Scan History')
        import_history_button.clicked.connect(self.import_scan_history)
        history_layout.addWidget(import_history_button)

        history_tab.setLayout(history_layout)
        self.tabs.addTab(history_tab, "Scan History")

    def run_scan(self):
        if self.process and self.process.poll() is None:
            QMessageBox.warning(self, "Scan in Progress", "A scan is already in progress.")
            return

        scan_name = self.scan_name_entry.text()
        target = self.target_entry.text()
        scan_type = self.get_scan_type(self.scan_type_combo.currentText())
        port_range = self.port_range_entry.text()
        custom_args = self.custom_args_entry.text()
        nse_scripts = self.nse_scripts_entry.text()

        cmd = ['nmap', scan_type]
        if port_range:
            cmd.extend(['-p', port_range])
        if custom_args:
            cmd.extend(custom_args.split())
        if nse_scripts:
            cmd.extend(['--script', nse_scripts])
        cmd.append(target)

        self.results_text.clear()
        self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.read_process_output(scan_name)

    def stop_scan(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.results_text.append("\nScan terminated by user.")
        else:
            QMessageBox.warning(self, "No Scan in Progress", "There is no scan currently in progress.")

    def read_process_output(self, scan_name):
        if self.process:
            output = self.process.stdout.read()
            self.results_text.append(output)
            if self.process.poll() is None:
                QTimer.singleShot(100, lambda: self.read_process_output(scan_name))
            else:
                self.save_scan_to_db({
                    'target': self.target_entry.text(),
                    'name': scan_name if scan_name else 'Manual Scan',
                    'scan_type': self.get_scan_type(self.scan_type_combo.currentText()),
                    'port_range': self.port_range_entry.text(),
                    'custom_args': self.custom_args_entry.text(),
                    'nse_scripts': self.nse_scripts_entry.text(),
                    'result': output
                })

    def get_scan_type(self, scan_type):
        scan_types = {
            'TCP Scan': '-sT',
            'UDP Scan': '-sU',
            'SYN Scan': '-sS',
            'Ping Scan': '-sn',
            'OS Detection': '-O',
            'ACK Scan': '-sA',
            'FIN Scan': '-sF',
            'Xmas Scan': '-sX',
            'NULL Scan': '-sN',
            'Window Scan': '-sW'
        }
        return scan_types.get(scan_type, '')

    def save_scan_to_db(self, scan):
        self.cursor.execute('''
            INSERT INTO scans (name, target, scan_type, port_range, custom_args, nse_scripts, result)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (scan['name'], scan['target'], scan['scan_type'], scan['port_range'], scan['custom_args'], scan['nse_scripts'], scan['result']))
        self.conn.commit()
        self.load_scan_history()

    def save_config(self):
        target = self.target_entry.text()
        scan_name = self.scan_name_entry.text()
        scan_type = self.scan_type_combo.currentText()
        port_range = self.port_range_entry.text()
        custom_args = self.custom_args_entry.text()
        nse_scripts = self.nse_scripts_entry.text()

        config = {
            'target': target,
            'name': scan_name,
            'scan_type': scan_type,
            'port_range': port_range,
            'custom_args': custom_args,
            'nse_scripts': nse_scripts
        }

        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Scan Configuration", "", "JSON Files (*.json);;All Files (*)", options=options)
        if file_path:
            with open(file_path, 'w') as f:
                json.dump(config, f, indent=4)
            QMessageBox.information(self, "Save Configuration", "Scan configuration saved successfully")

    def save_results_to_csv(self):
        scan_results = self.results_text.toPlainText()
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Results to CSV", "", "CSV Files (*.csv);;All Files (*)", options=options)
        if file_path:
            with open(file_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Scan Results'])
                writer.writerow([scan_results])
            QMessageBox.information(self, "Save Results", "Results saved successfully to CSV")

    def schedule_scan(self):
        scan_name = self.schedule_name_entry.text()
        target = self.schedule_target_entry.text()
        scan_type = self.get_scan_type(self.schedule_scan_type_combo.currentText())
        port_range = self.schedule_port_range_entry.text()
        custom_args = self.schedule_custom_args_entry.text()
        nse_scripts = self.schedule_nse_scripts_entry.text()
        schedule_time = self.datetime_edit.dateTime().toPyDateTime()

        self.scheduled_scans.append({
            'name': scan_name,
            'target': target,
            'scan_type': scan_type,
            'port_range': port_range,
            'custom_args': custom_args,
            'nse_scripts': nse_scripts,
            'schedule_time': schedule_time
        })
        QMessageBox.information(self, "Schedule Scan", f"Scan '{scan_name}' scheduled successfully for {schedule_time}")

    def run_scheduled_scans(self):
        current_time = QDateTime.currentDateTime().toPyDateTime()
        for scan in self.scheduled_scans[:]:
            if scan['schedule_time'] <= current_time:
                self.target_entry.setText(scan['target'])
                self.port_range_entry.setText(scan['port_range'])
                self.custom_args_entry.setText(scan['custom_args'])
                self.nse_scripts_entry.setText(scan['nse_scripts'])
                self.scan_name_entry.setText(scan['name'])
                self.scan_type_combo.setCurrentText(self.reverse_get_scan_type(scan['scan_type']))
                self.run_scan()
                self.scheduled_scans.remove(scan)

    def reverse_get_scan_type(self, scan_type_flag):
        scan_types = {
            '-sT': 'TCP Scan',
            '-sU': 'UDP Scan',
            '-sS': 'SYN Scan',
            '-sn': 'Ping Scan',
            '-O': 'OS Detection',
            '-sA': 'ACK Scan',
            '-sF': 'FIN Scan',
            '-sX': 'Xmas Scan',
            '-sN': 'NULL Scan',
            '-sW': 'Window Scan'
        }
        return scan_types.get(scan_type_flag, '')

    def add_to_history(self, scan):
        self.scan_history.append(scan)
        self.history_list.addItem(f"{scan['target']} - {scan['name']} - {scan['scan_type']}")

    def load_scan_from_history(self):
        selected_item = self.history_list.currentRow()
        if selected_item != -1:
            self.cursor.execute('SELECT * FROM scans WHERE id = ?', (selected_item + 1,))
            scan = self.cursor.fetchone()
            self.target_entry.setText(scan[2])
            self.port_range_entry.setText(scan[4])
            self.custom_args_entry.setText(scan[5])
            self.nse_scripts_entry.setText(scan[6])
            self.results_text.setText(scan[7])
            self.scan_name_entry.setText(scan[1])
            self.scan_type_combo.setCurrentText(self.reverse_get_scan_type(scan[3]))

    def delete_selected_history(self):
        selected_item = self.history_list.currentRow()
        if selected_item != -1:
            self.cursor.execute('DELETE FROM scans WHERE id = ?', (selected_item + 1,))
            self.conn.commit()
            self.history_list.takeItem(selected_item)

    def save_scan_history(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Scan History", "", "JSON Files (*.json);;All Files (*)", options=options)
        if file_path:
            self.cursor.execute('SELECT * FROM scans')
            scans = self.cursor.fetchall()
            scan_history = []
            for scan in scans:
                scan_history.append({
                    'name': scan[1],
                    'target': scan[2],
                    'scan_type': scan[3],
                    'port_range': scan[4],
                    'custom_args': scan[5],
                    'nse_scripts': scan[6],
                    'result': scan[7]
                })
            with open(file_path, 'w') as f:
                json.dump(scan_history, f, indent=4)
            QMessageBox.information(self, "Save History", "Scan history saved successfully")

    def import_scan_history(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        file_path, _ = QFileDialog.getOpenFileName(self, "Import Scan History", "", "JSON Files (*.json);;All Files (*)", options=options)
        if file_path:
            with open(file_path, 'r') as f:
                scan_history = json.load(f)
                for scan in scan_history:
                    self.cursor.execute('''
                        INSERT INTO scans (name, target, scan_type, port_range, custom_args, nse_scripts, result)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (scan['name'], scan['target'], scan['scan_type'], scan['port_range'], scan['custom_args'], scan['nse_scripts'], scan['result']))
                self.conn.commit()
                self.load_scan_history()
            QMessageBox.information(self, "Import History", "Scan history imported successfully")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = NmapApp()
    window.show()
    sys.exit(app.exec_())

