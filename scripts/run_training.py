from scripts.utils.load_config import config, BASE_DIR
from utilities.RWGuard.RWGuard import RWGuard
from utilities.ShieldFS.ShieldFS import ShieldFS
from utilities.CanCal.CanCal import CanCal

def run_training(framework: str, model: str):
    
    if framework == 'RWGuard':
        print("➡ Training RWGuard...\n")
        rwguard = RWGuard()
        rwguard.train_model(model)

    elif framework == 'ShieldFS':
        print("➡ Training ShieldFS...\n")
        shieldfs = ShieldFS()        
        shieldfs.train_model(model)

    elif framework == 'CanCal':
        print("➡ Training CanCal...\n")
        cancal = CanCal()        
        cancal.train_model(model)

    elif framework == 'Redemption':
        print("➡ No training for Redemption...\n")

    else:
        print(f"[run_training] Unsupported framework: {framework}\n")
        raise ValueError(f"Unknown framework: {framework}")

    print()