import yaml
import hashlib
from scripts.utils.load_config import config 

def calculate_hash(framework: str) -> str:
    if framework not in config:
        raise ValueError(f"Framework '{framework}' not found in config.")
    
    yaml_str = yaml.dump({framework: config[framework]}, sort_keys=True)

    return hashlib.sha256(yaml_str.encode("utf-8")).hexdigest()
