import argparse
from scripts.run_extraction import run_extraction
from scripts.run_training import run_training
from models.RWGuard.RWGuard import RWGuard

def parse_args():
    parser = argparse.ArgumentParser(description="Ransomware Detection Benchmarking Framework")

    parser.add_argument('--framework', type=str, required=True,
                        help='Feature extraction framework (e.g., rwguard, shieldfs)')
    
    parser.add_argument('--model', type=str, required=True,
                        help='Classifier model (e.g., random_forest, logistic_regression)')
    
    parser.add_argument('--mode', choices=['extract', 'train', 'all'], default='all',
                        help='What pipeline stage to run')

    return parser.parse_args()

def main():
    args = parse_args()

    print(f"Framework: {args.framework}")
    print(f"Model: {args.model}")
    print(f"Mode: {args.mode}")

    if args.mode in ['extract', 'all']:
        run_extraction(args.framework)

    if args.mode in ['train', 'all']:
        run_training(args.framework, args.model)
    
if __name__ == '__main__':
    main()
