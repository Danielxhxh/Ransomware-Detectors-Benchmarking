from scripts.utils.load_config import config, BASE_DIR
from utilities.RWGuard.RWGuard import RWGuard
from utilities.ShieldFS.ShieldFS import ShieldFS
from utilities.CanCal.CanCal import CanCal
from utilities.Redemption.Redemption import Redemption

def run_attack_evaluation(framework: str, model: str, saved_model: str):
    
    if framework == 'RWGuard':
        print("➡ Evaluating attack on RWGuard...\n")
        rwguard = RWGuard()
        rwguard.evaluate_attack(model, saved_model)

    elif framework == 'ShieldFS':
        print("➡ Evaluating attack on ShieldFS...\n")
        shieldfs = ShieldFS()
        shieldfs.evaluate_attack(model, saved_model)

    elif framework == 'CanCal':
        print("➡ Evaluating attack on CanCal...\n")
        cancal = CanCal()
        cancal.evaluate_attack(model, saved_model)

    elif framework == 'Redemption':
        print("➡ Evaluating attack on Redemption...\n")
        redemption = Redemption()
        redemption.evaluate_attack(model, saved_model)

    else:
        print(f"[run_attack_evaluation] Unsupported framework: {framework}")
        raise ValueError(f"Unknown framework: {framework}")
