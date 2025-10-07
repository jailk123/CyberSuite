# CyberSuite

A comprehensive and modular cybersecurity toolkit designed for both command-line and graphical user interface interaction. Developed as a portfolio project, CyberSuite aims to provide essential security utilities in a clean, user-friendly, and extensible package.

## Features

CyberSuite integrates several key cybersecurity tools:

-   **Password Generator**: Generate strong, customizable passwords.
-   **IP Lookup**: Obtain geographical and network information for IP addresses, with a free fallback if Shodan API is not configured.
-   **Port Scanner**: Perform fast, multithreaded TCP port scanning on target hosts.
-   **CVE Lookup**: Search the National Vulnerability Database (NVD) for Common Vulnerabilities and Exposures (CVEs) related to specific products and versions.
-   **Password Cracker**: Audit password strength by attempting to crack hashes against a wordlist (for educational and auditing purposes only).
-   **Log Monitor**: Monitor log files in real-time for user-defined patterns and trigger alerts.
-   **Reporting Module**: Generate consolidated Markdown reports from various tool outputs.

## Getting Started

### Prerequisites

-   Python 3.9+ installed.
-   `pip` (Python package installer).

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/jailk123/CyberSuite.git
    cd CyberSuite
    ```

2.  **Install dependencies:**
    ```bash
    pip install -e .
    ```
    This command installs all required Python packages and sets up the `cybersuite` command-line entry point.

### Configuration

Some tools (like Log Monitor) can utilize settings from a `config.ini` file.

1.  **Create `config.ini`:** Copy the example configuration:
    ```bash
    cp config.ini.example config.ini
    ```
    *(On Windows, use `copy config.ini.example config.ini`)*

2.  **Edit `config.ini`:** Open `config.ini` in a text editor and customize settings as needed. For example, you can define log file paths and monitoring rules under the `[LOG_MONITOR]` section.

    ```ini
    [DEFAULT]

    [LOG_MONITOR]
    # Path to the log file you want to monitor
    LOG_FILE_PATH = /path/to/your/log.log

    # Example rule: alert if the word "Failed" appears
    RULE_1_PATTERN = Failed
    RULE_1_NAME = Failed Login Attempt
    ```

    **Note:** Your `config.ini` is ignored by Git, ensuring sensitive information remains local.

## Usage

CyberSuite offers both a Command-Line Interface (CLI) and a Graphical User Interface (GUI).

### Command-Line Interface (CLI)

Run `cybersuite` followed by the command and its arguments.

```bash
cybersuite <command> [options]
```

**Commands:**

-   **`pass` (Password Generator)**
    ```bash
    cybersuite pass --length 20 --no-symbols
    ```

-   **`lookup` (IP Lookup)**
    ```bash
    cybersuite lookup 8.8.8.8
    ```

-   **`scan` (Port Scanner)**
    ```bash
    cybersuite scan example.com --ports 80,443,1000-2000 --threads 50
    ```

-   **`cvelookup` (CVE Lookup)**
    ```bash
    cybersuite cvelookup "apache http server" --version 2.4.50
    ```

-   **`crack` (Password Cracker)**
    ```bash
    # First, generate a hash (e.g., for 'mypassword')
    # python -c "import hashlib; print(hashlib.sha256(b'mypassword').hexdigest())"
    # Then, run the cracker with a wordlist
    cybersuite crack <your_hash_here> /path/to/wordlist.txt --algorithm sha256
    ```

-   **`monitor` (Log Monitor)**
    ```bash
    # Ensure LOG_FILE_PATH and rules are set in config.ini
    cybersuite monitor
    # Or specify a log file directly
    cybersuite monitor /path/to/another.log
    ```

-   **`report` (Reporting Module)**
    ```bash
    # Example: Create a dummy JSON file with some results
    # echo '{"ip_lookup": {"ip_str": "8.8.8.8", "country": "United States"}, "port_scan": {"target": "example.com", "open_ports": [{"port": 80, "service": "HTTP"}]}}' > results.json
    cybersuite report results.json output_report.md
    ```

### Graphical User Interface (GUI)

To launch the GUI, run the following command from the project root:

```bash
python gui/main_gui.py
```

The GUI provides an intuitive interface for all the tools, allowing you to input parameters and view results visually.

**GUI Screenshots:**

*(Placeholder for future GUI screenshots)*

## Building Executables

For distributing the CLI or GUI as standalone executables (e.g., `.exe` on Windows), `PyInstaller` can be used. It is recommended to build the multi-file version for stability.

```bash
# Build the CLI executable (multi-file version recommended)
pyinstaller --name CyberSuiteCLI cli/main_cli.py

# Build the GUI executable (multi-file version recommended)
pyinstaller --name CyberSuiteGUI gui/main_gui.py
```

The executables will be found in the `dist/` directory.

## Contributing

Contributions are welcome! Please feel free to fork the repository, make changes, and submit pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
