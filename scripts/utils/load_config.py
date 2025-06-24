import yaml
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
CONFIG_PATH = BASE_DIR / "config" / "config.yaml"

with open(CONFIG_PATH, 'r') as f:
    config = yaml.safe_load(f)
