import customtkinter as ctk
from tkinter import messagebox, filedialog
import threading
import os
import time
import json

# Import core functions
from cyber_suite_core.password_tools import generate_password, audit_password_hash
from cyber_suite_core.ip_lookup import lookup_ip
from cyber_suite_core.port_scanner import scan_ports, parse_port_range
from cyber_suite_core.cve_lookup import lookup_cves_by_product
from cyber_suite_core.log_monitor import LogMonitor, get_log_monitor_rules
from cyber_suite_core.reporting import generate_report
from cyber_suite_core.config_manager import config

class CyberSuiteGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("CyberSuite")
        self.geometry("1000x700")

        # Configure grid layout (4x4)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure((2, 3), weight=0)
        self.grid_rowconfigure((0, 1, 2), weight=1)

        # Create sidebar frame with widgets
        self.sidebar_frame = ctk.CTkFrame(self, width=140, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=8, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(7, weight=1)
        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="CyberSuite", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=20)

        # Fix for text visibility on light themes
        button_text_color = ("gray10", "gray90") # Dark text for light theme, light text for dark theme

        self.sidebar_button_1 = ctk.CTkButton(self.sidebar_frame, text="Password Generator", command=self.password_generator_frame_event, text_color=button_text_color)
        self.sidebar_button_1.grid(row=1, column=0, padx=20, pady=10)
        self.sidebar_button_2 = ctk.CTkButton(self.sidebar_frame, text="IP Lookup", command=self.ip_lookup_frame_event, text_color=button_text_color)
        self.sidebar_button_2.grid(row=2, column=0, padx=20, pady=10)
        self.sidebar_button_3 = ctk.CTkButton(self.sidebar_frame, text="Port Scanner", command=self.port_scanner_frame_event, text_color=button_text_color)
        self.sidebar_button_3.grid(row=3, column=0, padx=20, pady=10)
        self.sidebar_button_4 = ctk.CTkButton(self.sidebar_frame, text="CVE Lookup", command=self.cve_lookup_frame_event, text_color=button_text_color)
        self.sidebar_button_4.grid(row=4, column=0, padx=20, pady=10)
        self.sidebar_button_5 = ctk.CTkButton(self.sidebar_frame, text="Password Cracker", command=self.password_cracker_frame_event, text_color=button_text_color)
        self.sidebar_button_5.grid(row=5, column=0, padx=20, pady=10)
        self.sidebar_button_6 = ctk.CTkButton(self.sidebar_frame, text="Log Monitor", command=self.log_monitor_frame_event, text_color=button_text_color)
        self.sidebar_button_6.grid(row=6, column=0, padx=20, pady=10)
        self.sidebar_button_7 = ctk.CTkButton(self.sidebar_frame, text="Reporting", command=self.reporting_frame_event, text_color=button_text_color)
        self.sidebar_button_7.grid(row=7, column=0, padx=20, pady=10)

        self.appearance_mode_label = ctk.CTkLabel(self.sidebar_frame, text="Appearance Mode:", anchor="w")
        self.appearance_mode_label.grid(row=8, column=0, padx=20, pady=(10, 0))
        self.appearance_mode_optionemenu = ctk.CTkOptionMenu(self.sidebar_frame, values=["Light", "Dark", "System"], command=self.change_appearance_mode_event)
        self.appearance_mode_optionemenu.grid(row=9, column=0, padx=20, pady=(10, 10))

        # Create main frames for each tool
        self.password_generator_frame = self.create_password_generator_frame()
        self.ip_lookup_frame = self.create_ip_lookup_frame()
        self.port_scanner_frame = self.create_port_scanner_frame()
        self.cve_lookup_frame = self.create_cve_lookup_frame()
        self.password_cracker_frame = self.create_password_cracker_frame()
        self.log_monitor_frame = self.create_log_monitor_frame()
        self.reporting_frame = self.create_reporting_frame()

        # Set default frame
        self.select_frame_by_name("password_generator")

        # Log Monitor specific variables
        self.log_monitor_instance = None
        self.log_monitor_thread = None
        self.log_monitor_running = False

    def select_frame_by_name(self, name):
        # Set button color for selected button
        self.sidebar_button_1.configure(fg_color=("gray75", "gray25") if name == "password_generator" else "transparent")
        self.sidebar_button_2.configure(fg_color=("gray75", "gray25") if name == "ip_lookup" else "transparent")
        self.sidebar_button_3.configure(fg_color=("gray75", "gray25") if name == "port_scanner" else "transparent")
        self.sidebar_button_4.configure(fg_color=("gray75", "gray25") if name == "cve_lookup" else "transparent")
        self.sidebar_button_5.configure(fg_color=("gray75", "gray25") if name == "password_cracker" else "transparent")
        self.sidebar_button_6.configure(fg_color=("gray75", "gray25") if name == "log_monitor" else "transparent")
        self.sidebar_button_7.configure(fg_color=("gray75", "gray25") if name == "reporting" else "transparent")

        # Hide all frames
        for frame in [self.password_generator_frame, self.ip_lookup_frame, self.port_scanner_frame, 
                      self.cve_lookup_frame, self.password_cracker_frame, self.log_monitor_frame, 
                      self.reporting_frame]:
            frame.grid_forget()

        # Show selected frame
        if name == "password_generator":
            self.password_generator_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        elif name == "ip_lookup":
            self.ip_lookup_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        elif name == "port_scanner":
            self.port_scanner_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        elif name == "cve_lookup":
            self.cve_lookup_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        elif name == "password_cracker":
            self.password_cracker_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        elif name == "log_monitor":
            self.log_monitor_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        elif name == "reporting":
            self.reporting_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)

    def password_generator_frame_event(self):
        self.select_frame_by_name("password_generator")

    def ip_lookup_frame_event(self):
        self.select_frame_by_name("ip_lookup")

    def port_scanner_frame_event(self):
        self.select_frame_by_name("port_scanner")

    def cve_lookup_frame_event(self):
        self.select_frame_by_name("cve_lookup")

    def password_cracker_frame_event(self):
        self.select_frame_by_name("password_cracker")

    def log_monitor_frame_event(self):
        self.select_frame_by_name("log_monitor")

    def reporting_frame_event(self):
        self.select_frame_by_name("reporting")

    def change_appearance_mode_event(self, new_appearance_mode: str):
        ctk.set_appearance_mode(new_appearance_mode)

    def update_password_length_label(self, value):
        self.password_length_label.configure(text=f"{int(value)}")

    def generate_password_event(self):
        length = int(self.password_length_slider.get())
        uppercase = self.uppercase_var.get()
        lowercase = self.lowercase_var.get()
        digits = self.digits_var.get()
        symbols = self.symbols_var.get()

        password = generate_password(length, uppercase, lowercase, digits, symbols)
        if password:
            self.password_result_entry.delete(0, ctk.END)
            self.password_result_entry.insert(0, password)
        else:
            messagebox.showerror("Error", "At least one character set must be included!")

    def create_password_generator_frame(self):
        frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(8, weight=1)

        # Widgets for Password Generator
        label = ctk.CTkLabel(frame, text="Password Generator", font=ctk.CTkFont(size=24, weight="bold"))
        label.grid(row=0, column=0, pady=(0, 20))

        # Length
        length_frame = ctk.CTkFrame(frame, fg_color="transparent")
        length_frame.grid(row=1, column=0, sticky="ew", pady=5)
        length_frame.grid_columnconfigure(0, weight=1)
        length_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(length_frame, text="Length:").grid(row=0, column=0, sticky="w")
        self.password_length_slider = ctk.CTkSlider(length_frame, from_=8, to=64, number_of_steps=56, command=self.update_password_length_label)
        self.password_length_slider.set(16)
        self.password_length_slider.grid(row=0, column=1, sticky="ew", padx=(10,0))
        self.password_length_label = ctk.CTkLabel(length_frame, text=f"{int(self.password_length_slider.get())}")
        self.password_length_label.grid(row=0, column=2, padx=(10,0))

        # Checkboxes for character sets
        self.uppercase_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(frame, text="Include Uppercase (A-Z)", variable=self.uppercase_var).grid(row=2, column=0, sticky="w", pady=5)
        self.lowercase_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(frame, text="Include Lowercase (a-z)", variable=self.lowercase_var).grid(row=3, column=0, sticky="w", pady=5)
        self.digits_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(frame, text="Include Digits (0-9)", variable=self.digits_var).grid(row=4, column=0, sticky="w", pady=5)
        self.symbols_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(frame, text="Include Symbols (!@#$%%)", variable=self.symbols_var).grid(row=5, column=0, sticky="w", pady=5)

        # Generate Button
        generate_button = ctk.CTkButton(frame, text="Generate Password", command=self.generate_password_event)
        generate_button.grid(row=6, column=0, pady=(20, 10))

        # Result Display
        self.password_result_entry = ctk.CTkEntry(frame, placeholder_text="Generated Password", width=400, height=40, font=ctk.CTkFont(size=16))
        self.password_result_entry.grid(row=7, column=0, pady=10)

        return frame

    def create_ip_lookup_frame(self):
        frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(4, weight=1)

        label = ctk.CTkLabel(frame, text="IP Lookup", font=ctk.CTkFont(size=24, weight="bold"))
        label.grid(row=0, column=0, pady=(0, 20))

        ip_input_frame = ctk.CTkFrame(frame, fg_color="transparent")
        ip_input_frame.grid(row=1, column=0, sticky="ew", pady=5)
        ip_input_frame.grid_columnconfigure(0, weight=0)
        ip_input_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(ip_input_frame, text="IP Address:").grid(row=0, column=0, sticky="w", padx=(0,10))
        self.ip_lookup_entry = ctk.CTkEntry(ip_input_frame, placeholder_text="e.g., 8.8.8.8 or google.com")
        self.ip_lookup_entry.grid(row=0, column=1, sticky="ew")

        lookup_button = ctk.CTkButton(frame, text="Lookup IP", command=self.lookup_ip_event)
        lookup_button.grid(row=2, column=0, pady=(20, 10))

        self.ip_lookup_results_textbox = ctk.CTkTextbox(frame, width=500, height=200)
        self.ip_lookup_results_textbox.grid(row=3, column=0, sticky="nsew", pady=10)

        return frame

    def lookup_ip_event(self):
        ip_address = self.ip_lookup_entry.get()
        if not ip_address:
            messagebox.showerror("Error", "Please enter an IP address or domain.")
            return

        self.ip_lookup_results_textbox.delete("1.0", ctk.END)
        self.ip_lookup_results_textbox.insert("1.0", "Looking up IP...\n")
        
        # Run lookup in a separate thread to keep GUI responsive
        threading.Thread(target=self._run_ip_lookup, args=(ip_address,)).start()

    def _run_ip_lookup(self, ip_address):
        results = lookup_ip(ip_address)
        self.after(0, self._display_ip_lookup_results, results)

    def _display_ip_lookup_results(self, results):
        self.ip_lookup_results_textbox.delete("1.0", ctk.END)
        if results.get("error"):
            self.ip_lookup_results_textbox.insert("1.0", f"Error: {results['error']}\n", "error")
            if "fallback_data" in results:
                self.ip_lookup_results_textbox.insert(ctk.END, "Attempting fallback...\n", "info")
                self._display_ip_lookup_results(results["fallback_data"])
            return

        source = results.get("source", "Unknown")
        self.ip_lookup_results_textbox.insert(ctk.END, f"Source: {source}\n", "header")
        self.ip_lookup_results_textbox.insert(ctk.END, f"Target: {results.get('ip_str', results.get('query'))}\n", "header")
        self.ip_lookup_results_textbox.insert(ctk.END, "\n", "header")

        for key, value in results.items():
            if key in ["source", "ip_str", "query", "data", "vulnerabilities", "error"]:
                continue
            self.ip_lookup_results_textbox.insert(ctk.END, f"{key.replace('_', ' ').title()}: {value}\n")

        if source == "Shodan" and results.get('data'):
            self.ip_lookup_results_textbox.insert(ctk.END, "\nOpen Ports (Shodan):\n", "header")
            for port_data in results['data']:
                self.ip_lookup_results_textbox.insert(ctk.END, f"  Port: {port_data.get('port')}, Transport: {port_data.get('transport')}, Service: {port_data.get('product')}\n")

        self.ip_lookup_results_textbox.tag_config("error", foreground="red")
        self.ip_lookup_results_textbox.tag_config("header", foreground="blue", font=("TkDefaultFont", 10, "bold"))
        self.ip_lookup_results_textbox.tag_config("info", foreground="cyan")

    def create_port_scanner_frame(self):
        frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(6, weight=1)

        label = ctk.CTkLabel(frame, text="Port Scanner", font=ctk.CTkFont(size=24, weight="bold"))
        label.grid(row=0, column=0, pady=(0, 20))

        target_input_frame = ctk.CTkFrame(frame, fg_color="transparent")
        target_input_frame.grid(row=1, column=0, sticky="ew", pady=5)
        target_input_frame.grid_columnconfigure(0, weight=0)
        target_input_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(target_input_frame, text="Target (IP/Domain):").grid(row=0, column=0, sticky="w", padx=(0,10))
        self.port_scanner_target_entry = ctk.CTkEntry(target_input_frame, placeholder_text="e.g., example.com or 192.168.1.1")
        self.port_scanner_target_entry.grid(row=0, column=1, sticky="ew")

        ports_input_frame = ctk.CTkFrame(frame, fg_color="transparent")
        ports_input_frame.grid(row=2, column=0, sticky="ew", pady=5)
        ports_input_frame.grid_columnconfigure(0, weight=0)
        ports_input_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(ports_input_frame, text="Ports (e.g., 80, 1-1024):").grid(row=0, column=0, sticky="w", padx=(0,10))
        self.port_scanner_ports_entry = ctk.CTkEntry(ports_input_frame, placeholder_text="1-1024")
        self.port_scanner_ports_entry.grid(row=0, column=1, sticky="ew")

        threads_input_frame = ctk.CTkFrame(frame, fg_color="transparent")
        threads_input_frame.grid(row=3, column=0, sticky="ew", pady=5)
        threads_input_frame.grid_columnconfigure(0, weight=0)
        threads_input_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(threads_input_frame, text="Threads (default 100):").grid(row=0, column=0, sticky="w", padx=(0,10))
        self.port_scanner_threads_entry = ctk.CTkEntry(threads_input_frame, placeholder_text="100")
        self.port_scanner_threads_entry.grid(row=0, column=1, sticky="ew")

        scan_button = ctk.CTkButton(frame, text="Start Scan", command=self.start_port_scan_event)
        scan_button.grid(row=4, column=0, pady=(20, 10))

        self.port_scanner_results_textbox = ctk.CTkTextbox(frame, width=500, height=200)
        self.port_scanner_results_textbox.grid(row=5, column=0, sticky="nsew", pady=10)

        return frame

    def start_port_scan_event(self):
        target = self.port_scanner_target_entry.get()
        ports_str = self.port_scanner_ports_entry.get()
        threads_str = self.port_scanner_threads_entry.get()

        if not target:
            messagebox.showerror("Error", "Please enter a target IP or domain.")
            return
        if not ports_str:
            ports_str = "1-1024" # Default if empty
        try:
            threads = int(threads_str) if threads_str else 100
        except ValueError:
            messagebox.showerror("Error", "Number of threads must be an integer.")
            return

        self.port_scanner_results_textbox.delete("1.0", ctk.END)
        self.port_scanner_results_textbox.insert("1.0", "Starting port scan...\n")
        
        # Use a list to store progress updates from the thread
        self.scan_progress_updates = []
        self.scan_total_ports = len(parse_port_range(ports_str))
        self.scan_completed_ports = 0

        def progress_callback():
            self.scan_completed_ports += 1
            # Schedule GUI update on the main thread
            self.after(0, self._update_port_scan_progress)

        # Run scan in a separate thread
        threading.Thread(target=self._run_port_scan, args=(target, ports_str, threads, progress_callback)).start()

    def _update_port_scan_progress(self):
        progress_text = f"Scanning... {self.scan_completed_ports}/{self.scan_total_ports} ports checked.\n"
        # Only update if the last line is not the progress text to avoid flickering
        current_content = self.port_scanner_results_textbox.get("1.0", ctk.END)
        lines = current_content.splitlines()
        if not lines or not lines[-1].startswith("Scanning..."):
            self.port_scanner_results_textbox.insert(ctk.END, progress_text)
        else:
            self.port_scanner_results_textbox.delete(f"{self.port_scanner_results_textbox.index(ctk.END)} - 1 line", ctk.END)
            self.port_scanner_results_textbox.insert(ctk.END, progress_text)


    def _run_port_scan(self, target, ports_str, threads, progress_callback):
        results = scan_ports(target, ports_str, threads, progress_callback)
        self.after(0, self._display_port_scan_results, results)

    def _display_port_scan_results(self, results):
        self.port_scanner_results_textbox.delete("1.0", ctk.END)
        if results.get("error"):
            self.port_scanner_results_textbox.insert("1.0", f"Error: {results['error']}\n", "error")
            return

        self.port_scanner_results_textbox.insert(ctk.END, f"Scan complete for {results['target']} (resolved to {results['resolved_ip']}).\n\n")
        if results["open_ports"]:
            self.port_scanner_results_textbox.insert(ctk.END, "Open Ports:\n")
            for p in results["open_ports"]:
                self.port_scanner_results_textbox.insert(ctk.END, f"  Port {p['port']} ({p['service']}) is open\n")
        else:
            self.port_scanner_results_textbox.insert(ctk.END, "No open ports found in the specified range.\n")

        self.port_scanner_results_textbox.tag_config("error", foreground="red")

    def create_cve_lookup_frame(self):
        frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(5, weight=1)

        label = ctk.CTkLabel(frame, text="CVE Lookup", font=ctk.CTkFont(size=24, weight="bold"))
        label.grid(row=0, column=0, pady=(0, 20))

        product_input_frame = ctk.CTkFrame(frame, fg_color="transparent")
        product_input_frame.grid(row=1, column=0, sticky="ew", pady=5)
        product_input_frame.grid_columnconfigure(0, weight=0)
        product_input_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(product_input_frame, text="Product Name:").grid(row=0, column=0, sticky="w", padx=(0,10))
        self.cve_product_entry = ctk.CTkEntry(product_input_frame, placeholder_text="e.g., apache http server")
        self.cve_product_entry.grid(row=0, column=1, sticky="ew")

        version_input_frame = ctk.CTkFrame(frame, fg_color="transparent")
        version_input_frame.grid(row=2, column=0, sticky="ew", pady=5)
        version_input_frame.grid_columnconfigure(0, weight=0)
        version_input_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(version_input_frame, text="Version (Optional):").grid(row=0, column=0, sticky="w", padx=(0,10))
        self.cve_version_entry = ctk.CTkEntry(version_input_frame, placeholder_text="e.g., 2.4.50")
        self.cve_version_entry.grid(row=0, column=1, sticky="ew")

        lookup_button = ctk.CTkButton(frame, text="Lookup CVEs", command=self.cve_lookup_event)
        lookup_button.grid(row=3, column=0, pady=(20, 10))

        self.cve_lookup_results_textbox = ctk.CTkTextbox(frame, width=500, height=200)
        self.cve_lookup_results_textbox.grid(row=4, column=0, sticky="nsew", pady=10)

        return frame

    def cve_lookup_event(self):
        product = self.cve_product_entry.get()
        version = self.cve_version_entry.get()

        if not product:
            messagebox.showerror("Error", "Please enter a product name.")
            return

        self.cve_lookup_results_textbox.delete("1.0", ctk.END)
        self.cve_lookup_results_textbox.insert("1.0", f"Looking up CVEs for {product}{f' version {version}' if version else ''}...\n")

        threading.Thread(target=self._run_cve_lookup, args=(product, version)).start()

    def _run_cve_lookup(self, product, version):
        results = lookup_cves_by_product(product, version)
        self.after(0, self._display_cve_lookup_results, results)

    def _display_cve_lookup_results(self, results):
        self.cve_lookup_results_textbox.delete("1.0", ctk.END)
        if results.get("error"):
            self.cve_lookup_results_textbox.insert("1.0", f"Error: {results['error']}\n", "error")
            return

        self.cve_lookup_results_textbox.insert(ctk.END, f"CVE lookup complete for {results['product']}{f' version {results['version']}' if results['version'] else ''}.\n\n")

        if results["cves"]:
            self.cve_lookup_results_textbox.insert(ctk.END, "Found CVEs:\n")
            for cve in results["cves"]:
                self.cve_lookup_results_textbox.insert(ctk.END, f"  CVE ID: {cve['id']}\n")
                self.cve_lookup_results_textbox.insert(ctk.END, f"  CVSS Score: {cve['cvss_score']}\n")
                self.cve_lookup_results_textbox.insert(ctk.END, f"  Description: {cve['description']}\n\n")
        else:
            self.cve_lookup_results_textbox.insert(ctk.END, "No CVEs found for the specified product/version.\n")

        self.cve_lookup_results_textbox.tag_config("error", foreground="red")

    def create_password_cracker_frame(self):
        frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(6, weight=1)

        label = ctk.CTkLabel(frame, text="Password Cracker", font=ctk.CTkFont(size=24, weight="bold"))
        label.grid(row=0, column=0, pady=(0, 20))

        hash_input_frame = ctk.CTkFrame(frame, fg_color="transparent")
        hash_input_frame.grid(row=1, column=0, sticky="ew", pady=5)
        hash_input_frame.grid_columnconfigure(0, weight=0)
        hash_input_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(hash_input_frame, text="Hash:").grid(row=0, column=0, sticky="w", padx=(0,10))
        self.cracker_hash_entry = ctk.CTkEntry(hash_input_frame, placeholder_text="e.g., ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f")
        self.cracker_hash_entry.grid(row=0, column=1, sticky="ew")

        wordlist_input_frame = ctk.CTkFrame(frame, fg_color="transparent")
        wordlist_input_frame.grid(row=2, column=0, sticky="ew", pady=5)
        wordlist_input_frame.grid_columnconfigure(0, weight=0)
        wordlist_input_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(wordlist_input_frame, text="Wordlist File:").grid(row=0, column=0, sticky="w", padx=(0,10))
        self.cracker_wordlist_entry = ctk.CTkEntry(wordlist_input_frame, placeholder_text="path/to/wordlist.txt")
        self.cracker_wordlist_entry.grid(row=0, column=1, sticky="ew")
        ctk.CTkButton(wordlist_input_frame, text="Browse", command=self.browse_wordlist_file).grid(row=0, column=2, padx=(10,0))

        algorithm_input_frame = ctk.CTkFrame(frame, fg_color="transparent")
        algorithm_input_frame.grid(row=3, column=0, sticky="ew", pady=5)
        algorithm_input_frame.grid_columnconfigure(0, weight=0)
        algorithm_input_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(algorithm_input_frame, text="Algorithm:").grid(row=0, column=0, sticky="w", padx=(0,10))
        self.cracker_algorithm_optionmenu = ctk.CTkOptionMenu(algorithm_input_frame, values=["md5", "sha1", "sha256", "sha512"])
        self.cracker_algorithm_optionmenu.set("sha256")
        self.cracker_algorithm_optionmenu.grid(row=0, column=1, sticky="ew")

        crack_button = ctk.CTkButton(frame, text="Crack Password", command=self.crack_password_event)
        crack_button.grid(row=4, column=0, pady=(20, 10))

        self.cracker_results_textbox = ctk.CTkTextbox(frame, width=500, height=100)
        self.cracker_results_textbox.grid(row=5, column=0, sticky="nsew", pady=10)

        return frame

    def browse_wordlist_file(self):
        file_path = filedialog.askopenfilename(title="Select Wordlist File", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            self.cracker_wordlist_entry.delete(0, ctk.END)
            self.cracker_wordlist_entry.insert(0, file_path)

    def crack_password_event(self):
        hash_to_crack = self.cracker_hash_entry.get()
        wordlist_path = self.cracker_wordlist_entry.get()
        algorithm = self.cracker_algorithm_optionmenu.get()

        if not hash_to_crack or not wordlist_path:
            messagebox.showerror("Error", "Please provide a hash and a wordlist file.")
            return
        if not os.path.exists(wordlist_path):
            messagebox.showerror("Error", f"Wordlist file not found: {wordlist_path}")
            return

        self.cracker_results_textbox.delete("1.0", ctk.END)
        self.cracker_results_textbox.insert("1.0", "Cracking in progress...\n")

        threading.Thread(target=self._run_password_cracker, args=(hash_to_crack, wordlist_path, algorithm)).start()

    def _run_password_cracker(self, hash_to_crack, wordlist_path, algorithm):
        try:
            cracked_password = audit_password_hash(hash_to_crack, wordlist_path, algorithm)
            self.after(0, self._display_cracker_results, cracked_password, hash_to_crack)
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Error", f"Cracking failed: {e}"))

    def _display_cracker_results(self, cracked_password, original_hash):
        self.cracker_results_textbox.delete("1.0", ctk.END)
        if cracked_password:
            self.cracker_results_textbox.insert("1.0", f"Password cracked!\nOriginal: {cracked_password}\nHash: {original_hash}\n", "success")
        else:
            self.cracker_results_textbox.insert("1.0", "Password not found in wordlist.\n", "info")
        self.cracker_results_textbox.tag_config("success", foreground="green", font=("TkDefaultFont", 10, "bold"))
        self.cracker_results_textbox.tag_config("info", foreground="blue")

    def create_log_monitor_frame(self):
        frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(5, weight=1)

        label = ctk.CTkLabel(frame, text="Log Monitor", font=ctk.CTkFont(size=24, weight="bold"))
        label.grid(row=0, column=0, pady=(0, 20))

        log_file_input_frame = ctk.CTkFrame(frame, fg_color="transparent")
        log_file_input_frame.grid(row=1, column=0, sticky="ew", pady=5)
        log_file_input_frame.grid_columnconfigure(0, weight=0)
        log_file_input_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(log_file_input_frame, text="Log File Path:").grid(row=0, column=0, sticky="w", padx=(0,10))
        self.log_monitor_file_entry = ctk.CTkEntry(log_file_input_frame, placeholder_text="e.g., /var/log/auth.log or C:\\logs\\app.log")
        self.log_monitor_file_entry.grid(row=0, column=1, sticky="ew")
        ctk.CTkButton(log_file_input_frame, text="Browse", command=self.browse_log_file).grid(row=0, column=2, padx=(10,0))

        self.log_monitor_start_button = ctk.CTkButton(frame, text="Start Monitoring", command=self.start_log_monitor_event)
        self.log_monitor_start_button.grid(row=2, column=0, pady=(20, 10))
        self.log_monitor_stop_button = ctk.CTkButton(frame, text="Stop Monitoring", command=self.stop_log_monitor_event, state=ctk.DISABLED)
        self.log_monitor_stop_button.grid(row=3, column=0, pady=(0, 10))

        self.log_monitor_results_textbox = ctk.CTkTextbox(frame, width=500, height=200)
        self.log_monitor_results_textbox.grid(row=4, column=0, sticky="nsew", pady=10)

        return frame

    def browse_log_file(self):
        file_path = filedialog.askopenfilename(title="Select Log File", filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            self.log_monitor_file_entry.delete(0, ctk.END)
            self.log_monitor_file_entry.insert(0, file_path)

    def start_log_monitor_event(self):
        log_file_path = self.log_monitor_file_entry.get()
        if not log_file_path:
            log_file_path = config.get('LOG_MONITOR', 'LOG_FILE_PATH', fallback=None)
            if not log_file_path:
                messagebox.showerror("Error", "Log file path not specified and not found in config.ini.")
                return
        
        if not os.path.exists(log_file_path):
            messagebox.showerror("Error", f"Log file not found: {log_file_path}")
            return

        rules = get_log_monitor_rules()
        if not rules:
            messagebox.showwarning("Warning", "No log monitoring rules found in config.ini. Monitoring for all changes.")
            rules = [{'pattern': '.*', 'name': 'Any new line'}]

        self.log_monitor_results_textbox.delete("1.0", ctk.END)
        self.log_monitor_results_textbox.insert("1.0", f"Starting log monitor for {log_file_path}...\n")
        self.log_monitor_start_button.configure(state=ctk.DISABLED)
        self.log_monitor_stop_button.configure(state=ctk.NORMAL)

        def event_callback(event_data):
            self.after(0, self._display_log_event, event_data)

        self.log_monitor_instance = LogMonitor(log_file_path, rules, event_callback)
        self.log_monitor_thread = threading.Thread(target=self.log_monitor_instance.start, daemon=True)
        self.log_monitor_thread.start()
        self.log_monitor_running = True

    def _display_log_event(self, event_data):
        self.log_monitor_results_textbox.insert(ctk.END, f"ALERT ({event_data['rule_name']}): {event_data['log_line'].strip()} (Timestamp: {time.ctime(event_data['timestamp'])})\n", "alert")
        self.log_monitor_results_textbox.see(ctk.END) # Scroll to bottom
        self.log_monitor_results_textbox.tag_config("alert", foreground="red", font=("TkDefaultFont", 10, "bold"))

    def stop_log_monitor_event(self):
        if self.log_monitor_instance and self.log_monitor_running:
            self.log_monitor_instance.stop()
            self.log_monitor_instance = None
            self.log_monitor_thread = None
            self.log_monitor_running = False
            self.log_monitor_results_textbox.insert(ctk.END, "Log monitoring stopped.\n")
            self.log_monitor_start_button.configure(state=ctk.NORMAL)
            self.log_monitor_stop_button.configure(state=ctk.DISABLED)

    def create_reporting_frame(self):
        frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(4, weight=1)

        label = ctk.CTkLabel(frame, text="Reporting", font=ctk.CTkFont(size=24, weight="bold"))
        label.grid(row=0, column=0, pady=(0, 20))

        input_file_frame = ctk.CTkFrame(frame, fg_color="transparent")
        input_file_frame.grid(row=1, column=0, sticky="ew", pady=5)
        input_file_frame.grid_columnconfigure(0, weight=0)
        input_file_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(input_file_frame, text="Input JSON File:").grid(row=0, column=0, sticky="w", padx=(0,10))
        self.report_input_json_entry = ctk.CTkEntry(input_file_frame, placeholder_text="path/to/results.json")
        self.report_input_json_entry.grid(row=0, column=1, sticky="ew")
        ctk.CTkButton(input_file_frame, text="Browse", command=self.browse_report_input_json).grid(row=0, column=2, padx=(10,0))

        output_file_frame = ctk.CTkFrame(frame, fg_color="transparent")
        output_file_frame.grid(row=2, column=0, sticky="ew", pady=5)
        output_file_frame.grid_columnconfigure(0, weight=0)
        output_file_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(output_file_frame, text="Output Markdown File:").grid(row=0, column=0, sticky="w", padx=(0,10))
        self.report_output_md_entry = ctk.CTkEntry(output_file_frame, placeholder_text="report.md")
        self.report_output_md_entry.grid(row=0, column=1, sticky="ew")

        generate_button = ctk.CTkButton(frame, text="Generate Report", command=self.generate_report_event)
        generate_button.grid(row=3, column=0, pady=(20, 10))

        self.report_status_textbox = ctk.CTkTextbox(frame, width=500, height=100)
        self.report_status_textbox.grid(row=4, column=0, sticky="nsew", pady=10)

        return frame

    def browse_report_input_json(self):
        file_path = filedialog.askopenfilename(title="Select Input JSON File", filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if file_path:
            self.report_input_json_entry.delete(0, ctk.END)
            self.report_input_json_entry.insert(0, file_path)

    def generate_report_event(self):
        input_json_path = self.report_input_json_entry.get()
        output_md_path = self.report_output_md_entry.get()

        if not input_json_path or not output_md_path:
            messagebox.showerror("Error", "Please provide both input JSON and output Markdown file paths.")
            return
        if not os.path.exists(input_json_path):
            messagebox.showerror("Error", f"Input JSON file not found: {input_json_path}")
            return

        self.report_status_textbox.delete("1.0", ctk.END)
        self.report_status_textbox.insert("1.0", "Generating report...\n")

        threading.Thread(target=self._run_generate_report, args=(input_json_path, output_md_path)).start()

    def _run_generate_report(self, input_json_path, output_md_path):
        try:
            with open(input_json_path, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
            generate_report(report_data, output_md_path)
            self.after(0, lambda: self.report_status_textbox.insert(ctk.END, f"Report successfully generated to {output_md_path}\n", "success"))
        except FileNotFoundError:
            self.after(0, lambda: messagebox.showerror("Error", f"Input JSON file not found: {input_json_path}"))
        except json.JSONDecodeError:
            self.after(0, lambda: messagebox.showerror("Error", f"Invalid JSON format in input file: {input_json_path}"))
        except IOError as e:
            self.after(0, lambda: messagebox.showerror("Error", f"Could not write report: {e}"))
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Error", f"An unexpected error occurred during report generation: {e}"))
        self.report_status_textbox.tag_config("success", foreground="green", font=("TkDefaultFont", 10, "bold"))


if __name__ == "__main__":
    # Set appearance mode
    ctk.set_appearance_mode("System")  # Modes: "System" (default), "Dark", "Light"
    ctk.set_default_color_theme("blue")  # Themes: "blue" (default), "green", "dark-blue"

    app = CyberSuiteGUI()
    app.mainloop()