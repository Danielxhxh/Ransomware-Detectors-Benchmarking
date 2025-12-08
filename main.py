import argparse
from scripts.run_model_check import run_model_check
from scripts.run_extraction import run_extraction
from scripts.run_training import run_training
from scripts.run_evaluation import run_evaluation

def parse_args():
    parser = argparse.ArgumentParser(description="Ransomware Detection Benchmarking Framework")

    parser.add_argument('--framework', type=str, required=True,
                        help='Feature extraction framework (e.g., RWGuard, ShieldFS, CanCal)')
    
    parser.add_argument('--model', type=str, required=True,
                        help='Classifier model (e.g., random_forest, logistic_regression)')
    
    parser.add_argument('--mode', choices=['extract', 'train', 'evaluate', 'all'], default='all',
                        help='What pipeline stage to run')

    return parser.parse_args()

def main():
    print("\n🚀 Starting Benchmarking Framework\n")
    args = parse_args()

    print(f"Framework: {args.framework} | Model: {args.model} | Mode: {args.mode}\n")

    # TODO: This check the whole config of a framework
    # but we only need to check the model
    
    exists, saved_model_name = run_model_check(args.framework, args.model)
    if exists:
        run_evaluation(args.framework, args.model, saved_model_name)
    else:
        if args.mode in ['extract', 'all']:
            run_extraction(args.framework)

        if args.mode in ['train', 'all']:
            run_training(args.framework, args.model)

        if args.mode in ['evaluate', 'all']:
            run_evaluation(args.framework, args.model, saved_model_name)
    
if __name__ == '__main__':
    main()
