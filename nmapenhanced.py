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

    def scan(self, target, arguments):
        try:
            return self.nm.scan(hosts=target, arguments=arguments)
        except Exception as e:
            return f"Error: {e}"

class NmapApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Nmap GUI")
        self.scanner = NmapScanner()
        self.scan_history = []

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
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)

    def create_widgets(self):
        frame = tk.Frame(self.root)
        frame.pack(pady=10, padx=10)

        # Target Input Field
        tk.Label(frame, text="Target (IP or hostname):").grid(row=0, column=0, sticky='w')
        self.target_entry = tk.Entry(frame, width=50)
        self.target_entry.grid(row=0, column=1, pady=5)

        # Scan Type Selection
        tk.Label(frame, text="Select Scan Type:").grid(row=1, column=0, sticky='w')
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
            tk.Radiobutton(frame, text=text, variable=self.scan_type, value=value).grid(row=1, column=1 + i, sticky='w')

        # Custom Arguments Input Field
        tk.Label(frame, text="Custom Arguments (optional):").grid(row=2, column=0, sticky='w')
        self.custom_args_entry = tk.Entry(frame, width=50)
        self.custom_args_entry.grid(row=2, column=1, pady=5)

        # Custom Port Range Input Field
        tk.Label(frame, text="Port Range (optional):").grid(row=3, column=0, sticky='w')
        self.port_range_entry = tk.Entry(frame, width=50)
        self.port_range_entry.grid(row=3, column=1, pady=5)

        # Buttons
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10)

        self.scan_button = tk.Button(button_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=0, column=0, padx=5)

        self.export_button = tk.Button(button_frame, text="Export Results", command=self.export_results, state=tk.DISABLED)
        self.export_button.grid(row=0, column=1, padx=5)

        self.clear_button = tk.Button(button_frame, text="Clear Output", command=self.clear_output)
        self.clear_button.grid(row=0, column=2, padx=5)

        self.save_config_button = tk.Button(button_frame, text="Save Configuration", command=self.save_configuration)
        self.save_config_button.grid(row=0, column=3, padx=5)

        # Progress Bar
        self.progress = ttk.Progressbar(self.root, orient=tk.HORIZONTAL, length=100, mode='indeterminate')
        self.progress.pack(pady=5)

        # Output Area
        self.output_area = scrolledtext.ScrolledText(self.root, width=80, height=20)
        self.output_area.pack(pady=5)

        # Scan History
        tk.Label(self.root, text="Scan History:").pack(pady=5)
        self.history_listbox = tk.Listbox(self.root, width=80, height=5)
        self.history_listbox.pack(pady=5)
        self.history_listbox.bind('<<ListboxSelect>>', self.load_from_history)

    def create_status_bar(self):
        self.status = tk.StringVar()
        self.status.set("Ready")
        status_bar = tk.Label(self.root, textvariable=self.status, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def start_scan(self):
        target = self.target_entry.get()
        if not target:
            self.output_area.insert(tk.END, "Error: No target specified.\n")
            return

        scan_type = self.scan_type.get()
        custom_args = self.custom_args_entry.get()
        port_range = self.port_range_entry.get()

        if port_range:
            arguments = f"{scan_type} {custom_args} -p {port_range}".strip()
        else:
            arguments = f"{scan_type} {custom_args}".strip()

        # Disable the scan button to prevent multiple scans at the same time
        self.scan_button.config(state=tk.DISABLED)
        self.progress.start()
        self.status.set("Scanning...")

        # Run scan in a separate thread to keep the GUI responsive
        scan_thread = threading.Thread(target=self.run_scan, args=(target, arguments))
        scan_thread.start()

    def run_scan(self, target, arguments):
        result = self.scanner.scan(target, arguments)
        self.root.after(0, self.display_result, target, arguments, result)

    def display_result(self, target, arguments, result):
        self.progress.stop()
        self.scan_button.config(state=tk.NORMAL)
        self.status.set("Scan complete")
        self.output_area.insert(tk.END, f"Scanning {target} with arguments: {arguments}...\n")
        self.output_area.insert(tk.END, self.format_scan_result(result) + "\n")
        self.output_area.yview(tk.END)

        # Save to scan history
        self.scan_history.append((target, arguments, result))
        self.history_listbox.insert(tk.END, f"{target} ({arguments})")

        # Enable the export button after scan
        self.export_button.config(state=tk.NORMAL)

    def format_scan_result(self, result):
        if isinstance(result, str):  # If the result is an error message
            return result

        formatted_result = ""
        for host, data in result.get('scan', {}).items():
            formatted_result += f"Host: {host} ({data.get('hostnames', [{}])[0].get('name', 'unknown')})\n"
            formatted_result += f"State: {data.get('status', {}).get('state', 'unknown')}\n"
            for proto in data.get('tcp', {}):
                port = data['tcp'][proto]
                formatted_result += f"Port: {proto}\n"
                formatted_result += f"State: {port.get('state', 'unknown')}\n"
                formatted_result += f"Service: {port.get('name', 'unknown')}\n"
        return formatted_result

    def export_results(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("XML files", "*.xml")])
        if file_path:
            with open(file_path, 'w') as file:
                file.write(self.output_area.get("1.0", tk.END))
            messagebox.showinfo("Export", f"Results exported to {file_path}")

    def clear_output(self):
        self.output_area.delete("1.0", tk.END)

    def save_configuration(self):
        config = {
            'target': self.target_entry.get(),
            'scan_type': self.scan_type.get(),
            'custom_args': self.custom_args_entry.get(),
            'port_range': self.port_range_entry.get()
        }
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if file_path:
            with open(file_path, 'w') as file:
                json.dump(config, file)
            messagebox.showinfo("Save Configuration", f"Configuration saved to {file_path}")

    def load_from_history(self, event):
        selection = event.widget.curselection()
        if selection:
            index = selection[0]
            target, arguments, result = self.scan_history[index]
            self.output_area.insert(tk.END, f"\n\n--- Loaded from history ---\n")
            self.display_result(target, arguments, result)

    def show_about(self):
        messagebox.showinfo("About", "Nmap GUI\nVersion 1.0\nDeveloped by SherinJoseph")

if __name__ == "__main__":
    root = tk.Tk()
    app = NmapApp(root)
    root.mainloop()

