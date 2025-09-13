import yaml
import hashlib
from scripts.utils.load_config import config 

def calculate_hash(framework: str, model: str = None) -> str:
    if framework not in config:
        raise ValueError(f"Framework '{framework}' not found in config.")

    # Narrow down to just the requested model inside the framework (if provided)
    if model:
        if model not in config[framework]:
            raise ValueError(f"Model '{model}' not found in framework '{framework}'.")
        subset = {framework: {model: config[framework][model]}}
    else:
        # Hash the whole framework section
        subset = {framework: config[framework]}

    # Dump to YAML with sorted keys for consistency
    yaml_str = yaml.dump(subset, sort_keys=True)

    # Hash and return
    return hashlib.sha256(yaml_str.encode("utf-8")).hexdigest()
