from scripts.utils.load_config import config, BASE_DIR
from utilities.RWGuard.RWGuard import RWGuard
from utilities.ShieldFS.ShieldFS import ShieldFS

def run_evaluation(framework: str, model: str, saved_model: str):
    
    if framework == 'RWGuard':
        print("➡ Evaluating RWGuard...\n")
        rwguard = RWGuard()
        rwguard.evaluate(model, saved_model)

    elif framework == 'ShieldFS':
        print("➡ Evaluating ShieldFS...\n")
        shieldfs = ShieldFS()
        shieldfs.evaluate(model, saved_model)

    else:
        print(f"[run_training] Unsupported framework: {framework}")
        raise ValueError(f"Unknown framework: {framework}")
