import time
import re
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from typing import List, Dict, Any, Callable, Optional

from . import config_manager

class LogMonitorHandler(FileSystemEventHandler):
    """Handles file system events for log monitoring."""
    def __init__(self, log_file_path: str, rules: List[Dict[str, str]], callback: Callable[[Dict[str, str]], None]):
        self.log_file_path = log_file_path
        self.rules = rules
        self.callback = callback
        self.last_position = 0
        self._initialize_last_position()

    def _initialize_last_position(self):
        """Sets the initial read position to the end of the file."""
        try:
            with open(self.log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(0, os.SEEK_END)
                self.last_position = f.tell()
        except FileNotFoundError:
            pass # File might not exist yet

    def on_modified(self, event):
        """Called when a file or directory is modified."""
        if event.src_path == self.log_file_path:
            self.check_for_new_entries()

    def check_for_new_entries(self):
        """Reads new lines from the log file and applies rules."""
        try:
            with open(self.log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(self.last_position)
                new_content = f.read()
                self.last_position = f.tell()

                for line in new_content.splitlines():
                    if line.strip(): # Process non-empty lines
                        self._apply_rules(line)
        except FileNotFoundError:
            pass
        except Exception as e:
            # Log this error, but don't stop the monitor
            print(f"Error reading log file: {e}")

    def _apply_rules(self, line: str):
        """Applies defined rules to a single log line."""
        for rule in self.rules:
            pattern = rule['pattern']
            rule_name = rule['name']
            if re.search(pattern, line):
                self.callback({
                    'rule_name': rule_name,
                    'log_line': line,
                    'timestamp': time.time()
                })

class LogMonitor:
    """Monitors a log file for specific patterns and triggers callbacks."""
    def __init__(self, log_file_path: str, rules: List[Dict[str, str]], callback: Callable[[Dict[str, str]], None]):
        self.log_file_path = log_file_path
        self.rules = rules
        self.callback = callback
        self.observer = Observer()
        self.event_handler = LogMonitorHandler(log_file_path, rules, callback)

    def start(self):
        """Starts monitoring the log file."""
        # Ensure the directory exists for the observer
        log_dir = os.path.dirname(self.log_file_path)
        if not log_dir:
            log_dir = '.' # Monitor current directory if no path specified
        
        self.observer.schedule(self.event_handler, log_dir, recursive=False)
        self.observer.start()
        # Also check for any content that might have been added before starting the observer
        self.event_handler.check_for_new_entries()

    def stop(self):
        """Stops monitoring the log file."""
        self.observer.stop()
        self.observer.join()

def get_log_monitor_rules() -> List[Dict[str, str]]:
    """Retrieves log monitoring rules from the config manager."""
    rules = []
    log_config = config_manager.get_log_monitor_config()
    if log_config:
        i = 1
        while True:
            pattern_key = f'RULE_{i}_PATTERN'
            name_key = f'RULE_{i}_NAME'
            pattern = log_config.get(pattern_key)
            name = log_config.get(name_key)
            if pattern and name:
                rules.append({'pattern': pattern, 'name': name})
                i += 1
            else:
                break
    return rules
