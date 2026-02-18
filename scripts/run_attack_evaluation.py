from scripts.utils.load_config import config, BASE_DIR
from utilities.RWGuard.RWGuard import RWGuard
from utilities.ShieldFS.ShieldFS import ShieldFS
from utilities.CanCal.CanCal import CanCal
from utilities.Redemption.Redemption import Redemption

def run_attack_evaluation(framework: str, model: str, saved_model: str):
    
    # if framework == 'RWGuard':
    #     print("➡ Evaluating RWGuard...\n")
    #     rwguard = RWGuard()
    #     rwguard.evaluate(model, saved_model)

    # elif framework == 'ShieldFS':
    #     print("➡ Evaluating ShieldFS...\n")
    #     shieldfs = ShieldFS()
    #     shieldfs.evaluate(model, saved_model)

    # elif framework == 'CanCal':
    #     print("➡ Evaluating CanCal...\n")
    #     cancal = CanCal()
    #     cancal.evaluate(model, saved_model)

    if framework == 'Redemption':
        print("➡ Evaluating attack on Redemption...\n")
        redemption = Redemption()
        redemption.evaluate_attack(model, saved_model)

    else:
        print(f"[run_attack_evaluation] Unsupported framework: {framework}")
        raise ValueError(f"Unknown framework: {framework}")
