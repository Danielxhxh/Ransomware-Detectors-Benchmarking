import logging

def run_training(framework: str, model: str):
    logging.info(f"[run_training] Called with framework: {framework}, model: {model}")

    if framework == 'rwguard':
        print(f"→ Training model '{model}' using RWGuard features...")
    elif framework == 'shieldfs':
        print(f"→ Training model '{model}' using ShieldFS features...")
    else:
        logging.error(f"[run_training] Unsupported framework: {framework}")
        raise ValueError(f"Unknown framework: {framework}")
