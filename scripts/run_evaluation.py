from scripts.utils.load_config import config, BASE_DIR
from utilities.RWGuard.RWGuard import RWGuard
from utilities.ShieldFS.ShieldFS import ShieldFS

def run_evaluation(framework: str, saved_model: str):
    
    if framework == 'RWGuard':
        rwguard = RWGuard()
        rwguard.evaluate(saved_model)

    elif framework == 'ShieldFS':
        shieldfs = ShieldFS()
        shieldfs.evaluate(saved_model)

    else:
        print(f"[run_training] Unsupported framework: {framework}")
        raise ValueError(f"Unknown framework: {framework}")
