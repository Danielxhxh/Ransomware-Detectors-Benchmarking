from scripts.utils.load_config import config, BASE_DIR
from models.RWGuard.RWGuard import RWGuard

def run_training(framework: str, model: str):
    
    if framework == 'rwguard':
        rwguard = RWGuard()
        rwguard.train_model(model)

    elif framework == 'shieldfs':
        print(f"→ Training model '{model}' using ShieldFS features...")
    else:
        print(f"[run_training] Unsupported framework: {framework}")
        raise ValueError(f"Unknown framework: {framework}")
