from scripts.utils.load_config import config, BASE_DIR
from utilities.RWGuard.RWGuard import RWGuard
from utilities.ShieldFS.ShieldFS import ShieldFS
from utilities.CanCal.CanCal import CanCal
from utilities.Redemption.Redemption import Redemption

def handle_extraction(filename, extractor_fn, label: str):
    if filename.exists():
        print(f"    ✅ Skipping {label} extraction — file already exists: {filename.name}")
    else:
        extractor_fn()


def run_extraction(framework: str):
    datasets_path = BASE_DIR / 'datasets' / f'{framework}'

    if framework == 'RWGuard':
        TIME_WINDOW = config['RWGuard']['time_window']
        rwguard = RWGuard()

        print("➡ Extracting RWGuard features...\n")

        benign_filename = datasets_path / f'benign_rwguard_features_{TIME_WINDOW}sec.csv'
        ransom_filename = datasets_path / f'ransomware_rwguard_features_{TIME_WINDOW}sec.csv'

        handle_extraction(benign_filename, rwguard.extract_benign_features, "benign")
        handle_extraction(ransom_filename, rwguard.extract_ransomware_features, "ransomware")

    elif framework == 'ShieldFS':
        TIER = config['ShieldFS']['tiers']
        shieldfs = ShieldFS()

        print("→ Extracting ShieldFS features...\n")

        benign_filename = datasets_path / 'process_centric' / 'benign' / f'tier{TIER}' / 'all_ticks.csv'
        ransom_filename = datasets_path / 'process_centric' / 'ransomware' / f'tier{TIER}' / 'all_ticks.csv'

        handle_extraction(benign_filename, shieldfs.extract_benign_features, "benign")
        handle_extraction(ransom_filename, shieldfs.extract_ransomware_features, "ransomware")
    
    elif framework == 'CanCal':
        TIME_WINDOW = config['CanCal']['time_window']
        cancal = CanCal()

        print("➡ Extracting CanCal features...\n")

        benign_filename = datasets_path / f'benign_cancal_features_{TIME_WINDOW}sec.csv'
        ransom_filename = datasets_path / f'ransomware_cancal_features_{TIME_WINDOW}sec.csv'

        handle_extraction(benign_filename, cancal.extract_benign_features, "benign")
        handle_extraction(ransom_filename, cancal.extract_ransomware_features, "ransomware")
    
    elif framework == 'Redemption':
        redemption = Redemption()

        print("➡ Extracting Redemption features...\n")
        benign_filename = datasets_path / f'benign_redemption_features.csv'
        ransom_filename = datasets_path / f'ransomware_redemption_features.csv'
        handle_extraction(benign_filename, redemption.extract_benign_features, "benign")
        handle_extraction(ransom_filename, redemption.extract_ransomware_features, "ransomware")
    
    else:
        raise ValueError(f"Unknown framework: {framework}")

    print()
