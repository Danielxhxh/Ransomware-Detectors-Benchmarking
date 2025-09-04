from scripts.utils.load_config import config, BASE_DIR
from utilities.RWGuard.RWGuard import RWGuard
from utilities.ShieldFS.ShieldFS import ShieldFS

def run_extraction(framework: str):
    datasets_path = BASE_DIR / 'datasets' / f'{framework}'

    if framework == 'RWGuard':
        TIME_WINDOW = config['RWGuard']['time_window']
        rwguard = RWGuard()
        
        print("➡ Extracting RWGuard features...")

        benign_filename = datasets_path / f'benign_rwguard_features_{TIME_WINDOW}sec.csv'
        ransom_filename = datasets_path / f'ransomware_rwguard_features_{TIME_WINDOW}sec.csv'

        if benign_filename.exists():
            print(f"✅ Skipping benign extraction — file already exists: {benign_filename.name}")
        else:
            rwguard.extract_benign_features()
        if ransom_filename.exists():
            print(f"✅ Skipping ransomware extraction — file already exists: {ransom_filename.name}")
        else:
            rwguard.extract_ransomware_features()

    elif framework == 'ShieldFS':
        TIER = config['ShieldFS']['tiers']
        shieldfs = ShieldFS()

        print("→ Extracting ShieldFS features...")

        benign_filename = datasets_path / 'process_centric' / 'benign' / f'tier{TIER}' / 'all_ticks.csv'
        ransom_filename = datasets_path / 'process_centric' / 'ransomware' / f'tier{TIER}' / 'all_ticks.csv'

        if benign_filename.exists():
            print(f"✅ Skipping benign extraction — file already exists: {benign_filename.name}")
        else:
            shieldfs.extract_benign_features()
        if ransom_filename.exists():
            print(f"✅ Skipping ransomware extraction — file already exists: {ransom_filename.name}")
        else:
            shieldfs.extract_ransomware_features()


    else:
        raise ValueError(f"Unknown framework: {framework}")

