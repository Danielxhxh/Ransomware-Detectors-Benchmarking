from scripts.utils.load_config import BASE_DIR
from scripts.utils.calculate_hash import calculate_hash
import os

def run_model_check(framework: str) -> tuple[bool, str]:
    hash_value = calculate_hash(framework)
    target_file = f"{hash_value}.pkl"

    saved_models_path = BASE_DIR / 'saved_models'
    files = os.listdir(saved_models_path)

    exists = target_file in files
    return exists, target_file
