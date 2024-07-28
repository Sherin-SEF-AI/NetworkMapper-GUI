import sys
import subprocess
import json
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, 
    QTextEdit, QRadioButton, QFileDialog, QDateTimeEdit, QMessageBox, QListWidget, 
    QComboBox, QGroupBox, QFormLayout, QTabWidget
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
        self.scan_history = []
        self.process = None
        self.timer = QTimer()
        self.timer.timeout.connect(self.run_scheduled_scans)
        self.timer.start(1000)

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
                self.add_to_history({
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

    def save_config(self):
        target = self.target_entry.text()
        scan_name = self.scan_name_entry.text()
        scan_type = self.get_scan_type(self.scan_type_combo.currentText())
        port_range = self.port_range_entry.text()
        custom_args = self.custom_args_entry.text()
        nse_scripts = self.nse_scripts_entry.text()

        config = {
            'name': scan_name,
            'target': target,
            'scan_type': scan_type,
            'port_range': port_range,
            'custom_args': custom_args,
            'nse_scripts': nse_scripts
        }

        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Scan Config", "", "JSON Files (*.json);;All Files (*)", options=options)
        if file_path:
            with open(file_path, 'w') as f:
                json.dump(config, f, indent=4)
            QMessageBox.information(self, "Save Config", "Configuration saved successfully")

    def save_results_to_csv(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Results to CSV", "", "CSV Files (*.csv);;All Files (*)", options=options)
        if file_path:
            scan_results = self.results_text.toPlainText()
            with open(file_path, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
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
                self.run_scan()
                self.scheduled_scans.remove(scan)

    def add_to_history(self, scan):
        self.scan_history.append(scan)
        self.history_list.addItem(f"{scan['target']} - {scan['name']} - {scan['scan_type']}")

    def load_scan_from_history(self):
        selected_item = self.history_list.currentRow()
        if selected_item != -1:
            scan = self.scan_history[selected_item]
            self.target_entry.setText(scan['target'])
            self.port_range_entry.setText(scan['port_range'])
            self.custom_args_entry.setText(scan['custom_args'])
            self.nse_scripts_entry.setText(scan['nse_scripts'])
            self.results_text.setText(scan['result'])
            self.scan_name_entry.setText(scan['name'])

    def delete_selected_history(self):
        selected_item = self.history_list.currentRow()
        if selected_item != -1:
            del self.scan_history[selected_item]
            self.history_list.takeItem(selected_item)

    def save_scan_history(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Scan History", "", "JSON Files (*.json);;All Files (*)", options=options)
        if file_path:
            with open(file_path, 'w') as f:
                json.dump(self.scan_history, f, indent=4)
            QMessageBox.information(self, "Save History", "Scan history saved successfully")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = NmapApp()
    window.show()
    sys.exit(app.exec_())

