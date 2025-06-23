import logging
from extractors.RWGuard import fv_benign as rw_benign, fv_ransomware as rw_ransom
from extractors.ShieldFS import fv_benign as sf_benign, fv_ransomware as sf_ransom

def run_extraction(framework: str):
    logging.info(f"[run_extraction] Called with framework: {framework}")

    if framework == 'rwguard':
        print("→ Extracting RWGuard features...")
        rw_benign.main()
        rw_ransom.main()

    elif framework == 'shieldfs':
        print("→ Extracting ShieldFS features...")
        sf_benign.main()
        sf_ransom.main()

    else:
        raise ValueError(f"Unknown framework: {framework}")
