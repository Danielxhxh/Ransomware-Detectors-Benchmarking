from scripts.utils.load_config import config, BASE_DIR
from extractors.RWGuard import fv_benign as rwguard_fv_benign, fv_ransomware as rwguard_fv_ransomware

def run_extraction(framework: str):
    TIME_WINDOW = config['time_window']

    if framework == 'rwguard':
        print("→ Extracting RWGuard features...")

        output_dir = BASE_DIR / 'datasets' / 'features' / 'RWGuard'
        benign_filename = output_dir / f'benign_rwguard_features_{TIME_WINDOW}sec.csv'
        ransom_filename = output_dir / f'ransomware_rwguard_features_{TIME_WINDOW}sec.csv'

        if benign_filename.exists():
            print(f"✔ Skipping benign extraction — file already exists: {benign_filename.name}")
        else:
            rwguard_fv_benign.extract_features()
        if ransom_filename.exists():
            print(f"✔ Skipping ransomware extraction — file already exists: {ransom_filename.name}")
        else:
            rwguard_fv_ransomware.extract_features()

    elif framework == 'shieldfs':
        print("→ Extracting ShieldFS features...")
        # Add similar logic here for ShieldFS

    else:
        raise ValueError(f"Unknown framework: {framework}")

