import configparser
import os

# The name of the configuration file.
CONFIG_FILE = 'config.ini'

# Initialize a new config parser.
config = configparser.ConfigParser()

# Check if the config file exists and read it.
if os.path.exists(CONFIG_FILE):
    config.read(CONFIG_FILE)
else:
    # You might want to log this or handle it gracefully.
    # For now, it will just have empty sections if the file doesn't exist.
    pass

def get_shodan_api_key():
    """Safely retrieves the Shodan API key from the config file."""
    return config.get('SHODAN', 'API_KEY', fallback=None)

def get_log_monitor_config():
    """Retrieves log monitoring configuration."""
    if 'LOG_MONITOR' in config:
        return config['LOG_MONITOR']
    return None

# You can add more functions here to get other configuration values.
