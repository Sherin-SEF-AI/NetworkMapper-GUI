import os
import sys
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox, ttk
import nmap
import json
import threading

class NmapScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.is_scanning = False

    def scan(self, target, arguments):
        try:
            self.is_scanning = True
            return self.nm.scan(hosts=target, arguments=arguments)
        except Exception as e:
            return f"Error: {e}"
        finally:
            self.is_scanning = False

    def stop_scan(self):
        if self.is_scanning:
            self.nm.stop()
            self.is_scanning = False
            return "Scan stopped."
        return "No scan to stop."

class NmapApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Nmap GUI")
        self.scanner = NmapScanner()
        self.scan_thread = None

        # Create Menu
        self.create_menu()

        # Create Widgets
        self.create_widgets()

        # Create Status Bar
        self.create_status_bar()

    def create_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Results", command=self.export_results)
        file_menu.add_command(label="Save Configuration", command=self.save_configuration)
        file_menu.add_command(label="Load Configuration", command=self.load_configuration)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)

    def create_widgets(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(pady=10, padx=10, expand=True)

        self.basic_tab = tk.Frame(notebook)
        self.advanced_tab = tk.Frame(notebook)
        self.results_tab = tk.Frame(notebook)
        self.cheatsheet_tab = tk.Frame(notebook)

        notebook.add(self.basic_tab, text="Basic Scan")
        notebook.add(self.advanced_tab, text="Advanced Scan")
        notebook.add(self.results_tab, text="Results")
        notebook.add(self.cheatsheet_tab, text="Nmap Cheat Sheet")

        # Basic Tab Widgets
        self.create_basic_tab_widgets()

        # Advanced Tab Widgets
        self.create_advanced_tab_widgets()

        # Results Tab Widgets
        self.create_results_tab_widgets()

        # Cheat Sheet Tab Widgets
        self.create_cheatsheet_tab_widgets()

    def create_basic_tab_widgets(self):
        tk.Label(self.basic_tab, text="Target (IP or hostname):").grid(row=0, column=0, sticky='w')
        self.target_entry = tk.Entry(self.basic_tab, width=50)
        self.target_entry.grid(row=0, column=1, pady=5)

        tk.Label(self.basic_tab, text="Select Scan Type:").grid(row=1, column=0, sticky='w')
        self.scan_type = tk.StringVar(value='-sS')
        scan_types = {
            'TCP SYN Scan': '-sS',
            'UDP Scan': '-sU',
            'Service Version Detection': '-sV',
            'OS Detection': '-O',
            'Aggressive Scan': '-A',
            'Ping Scan': '-sn',
            'Traceroute': '--traceroute'
        }
        for i, (text, value) in enumerate(scan_types.items()):
            tk.Radiobutton(self.basic_tab, text=text, variable=self.scan_type, value=value).grid(row=2, column=i, sticky='w')

        tk.Label(self.basic_tab, text="Port Range (optional):").grid(row=3, column=0, sticky='w')
        self.port_range_entry = tk.Entry(self.basic_tab, width=50)
        self.port_range_entry.grid(row=3, column=1, pady=5)

        tk.Button(self.basic_tab, text="Start Scan", command=self.start_scan).grid(row=4, column=0, pady=10)
        tk.Button(self.basic_tab, text="Stop Scan", command=self.stop_scan).grid(row=4, column=1, pady=10)

    def create_advanced_tab_widgets(self):
        tk.Label(self.advanced_tab, text="Target (IP or hostname):").grid(row=0, column=0, sticky='w')
        self.adv_target_entry = tk.Entry(self.advanced_tab, width=50)
        self.adv_target_entry.grid(row=0, column=1, pady=5)

        tk.Label(self.advanced_tab, text="Custom Arguments:").grid(row=1, column=0, sticky='w')
        self.custom_args_entry = tk.Entry(self.advanced_tab, width=50)
        self.custom_args_entry.grid(row=1, column=1, pady=5)

        tk.Label(self.advanced_tab, text="NSE Scripts (optional):").grid(row=2, column=0, sticky='w')
        self.nse_scripts_entry = tk.Entry(self.advanced_tab, width=50)
        self.nse_scripts_entry.grid(row=2, column=1, pady=5)

        tk.Button(self.advanced_tab, text="Start Advanced Scan", command=self.start_advanced_scan).grid(row=3, column=0, pady=10)
        tk.Button(self.advanced_tab, text="Stop Scan", command=self.stop_scan).grid(row=3, column=1, pady=10)

    def create_results_tab_widgets(self):
        self.results_text = scrolledtext.ScrolledText(self.results_tab, width=80, height=20)
        self.results_text.pack(pady=10, padx=10, fill='both', expand=True)

    def create_cheatsheet_tab_widgets(self):
        cheatsheet_text = scrolledtext.ScrolledText(self.cheatsheet_tab, width=80, height=20)
        cheatsheet_text.pack(pady=10, padx=10, fill='both', expand=True)

        cheatsheet_content = """
        Nmap Cheat Sheet
        ----------------
        Basic Scans:
        - TCP SYN Scan: nmap -sS <target>
        - UDP Scan: nmap -sU <target>
        - Service Version Detection: nmap -sV <target>
        - OS Detection: nmap -O <target>
        - Aggressive Scan: nmap -A <target>
        - Ping Scan: nmap -sn <target>
        - Traceroute: nmap --traceroute <target>

        Host Discovery:
        - Disable host discovery: nmap -Pn <target>
        - ICMP echo request: nmap -PE <target>
        - TCP SYN discovery on port 443: nmap -PS443 <target>
        - UDP discovery on port 53: nmap -PU53 <target>

        Port Scanning:
        - Scan specific ports: nmap -p 22,80,443 <target>
        - Scan port ranges: nmap -p 1-65535 <target>
        - Fast scan (100 most common ports): nmap -F <target>

        NSE Scripts:
        - List available scripts: nmap --script-help
        - Run a specific script: nmap --script <script-name> <target>
        - Run multiple scripts: nmap --script <script1>,<script2> <target>
        """
        cheatsheet_text.insert(tk.END, cheatsheet_content)
        cheatsheet_text.config(state=tk.DISABLED)

    def create_status_bar(self):
        self.status = tk.StringVar()
        self.status.set("Ready")
        status_bar = tk.Label(self.root, textvariable=self.status, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def start_scan(self):
        target = self.target_entry.get()
        if not target:
            self.results_text.insert(tk.END, "Error: No target specified.\n")
            return

        scan_type = self.scan_type.get()
        port_range = self.port_range_entry.get()

        if port_range:
            arguments = f"{scan_type} -p {port_range}".strip()
        else:
            arguments = scan_type

        self.run_scan(target, arguments)

    def start_advanced_scan(self):
        target = self.adv_target_entry.get()
        if not target:
            self.results_text.insert(tk.END, "Error: No target specified.\n")
            return

        custom_args = self.custom_args_entry.get()
        nse_scripts = self.nse_scripts_entry.get()

        arguments = f"{custom_args} {nse_scripts}".strip()
        self.run_scan(target, arguments)

    def run_scan(self, target, arguments):
        self.status.set("Scanning...")
        self.results_text.insert(tk.END, f"Scanning {target} with arguments: {arguments}...\n")

        self.scan_thread = threading.Thread(target=self.scan_thread_func, args=(target, arguments))
        self.scan_thread.start()

    def scan_thread_func(self, target, arguments):
        result = self.scanner.scan(target, arguments)
        self.root.after(0, self.display_result, target, arguments, result)

    def display_result(self, target, arguments, result):
        self.status.set("Scan complete")
        self.results_text.insert(tk.END, f"Scan results for {target} with arguments {arguments}:\n")
        self.results_text.insert(tk.END, self.format_scan_result(result) + "\n")

    def format_scan_result(self, result):
        if isinstance(result, str):
            return result
        
        formatted_result = ""
        for host, host_info in result['scan'].items():
            formatted_result += f"Host: {host}\n"
            for proto in host_info.get('tcp', {}):
                formatted_result += f"Port: {proto}\tState: {host_info['tcp'][proto].get('state', 'unknown')}\tService: {host_info['tcp'][proto].get('name', 'unknown')}\tVersion: {host_info['tcp'][proto].get('version', 'unknown')}\n"
        return formatted_result

    def stop_scan(self):
        stop_message = self.scanner.stop_scan()
        self.results_text.insert(tk.END, stop_message + "\n")
        self.status.set("Ready")

    def export_results(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'w') as file:
                file.write(self.results_text.get(1.0, tk.END))
            messagebox.showinfo("Export Results", f"Results exported to {file_path}")

    def save_configuration(self):
        target = self.target_entry.get()
        arguments = self.scan_type.get()
        port_range = self.port_range_entry.get()

        config = {
            'target': target,
            'arguments': arguments,
            'port_range': port_range
        }

        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'w') as file:
                json.dump(config, file)
            messagebox.showinfo("Save Configuration", f"Configuration saved to {file_path}")

    def load_configuration(self):
        file_path = filedialog.askopenfilename(defaultextension=".json", filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'r') as file:
                config = json.load(file)
            self.target_entry.delete(0, tk.END)
            self.target_entry.insert(0, config['target'])
            self.scan_type.set(config['arguments'])
            self.port_range_entry.delete(0, tk.END)
            self.port_range_entry.insert(0, config['port_range'])

    def show_about(self):
        messagebox.showinfo("About", "Nmap GUI\nVersion 2.0\nSherinJosephRoy")

if __name__ == "__main__":
    root = tk.Tk()
    app = NmapApp(root)
    root.mainloop()

