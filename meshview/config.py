import configparser
import argparse

# Parse command-line arguments
parser = argparse.ArgumentParser(description="MeshView Configuration Loader")
parser.add_argument("--config", type=str, default="config.ini", help="Path to config.ini file (default: config.ini)")
args = parser.parse_args()

# Initialize config parser
config_parser = configparser.ConfigParser()
if not config_parser.read(args.config):
    raise FileNotFoundError(f"Config file '{args.config}' not found! Ensure the file exists.")

CONFIG = {section: dict(config_parser.items(section)) for section in config_parser.sections()}

# Parse channel keys from config
def get_channel_keys():
    """Extract and parse channel keys from the MQTT section."""
    mqtt_section = CONFIG.get("mqtt", {})
    channel_keys_str = mqtt_section.get("channel_keys", "1PG7OiApB1nwvP+rz05pAQ==")
    
    # Split by comma and strip whitespace
    keys = [key.strip() for key in channel_keys_str.split(",") if key.strip()]
    return keys

# Make channel keys available
CHANNEL_KEYS = get_channel_keys()

