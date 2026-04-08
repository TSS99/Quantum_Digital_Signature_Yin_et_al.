import argparse

from qds_beginner import (
    compute_security_params,
    format_beginner_terms,
    format_result_summary,
    run_qds_protocol,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a beginner-friendly end-to-end Quantum Digital Signature demo."
    )
    parser.add_argument(
        "--document",
        default="Hello, QDS!",
        help="Message to sign in the demo.",
    )
    parser.add_argument(
        "--bits",
        type=int,
        default=500,
        help="Document length bM in bits after encoding.",
    )
    parser.add_argument(
        "--epsilon",
        type=float,
        default=1e-10,
        help="Target total security bound.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Hide the step-by-step protocol printout and show only the summary.",
    )
    parser.add_argument(
        "--show-terms",
        action="store_true",
        help="Print a short glossary of the main symbols before running the demo.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    params = compute_security_params(args.bits, args.epsilon)

    print("Quantum Digital Signature beginner demo")
    print("=" * 45)
    print(f"Document           : {args.document}")
    print(f"Document size (bM) : {args.bits}")
    print(f"Target epsilon     : {args.epsilon:.1e}")
    print(f"Chosen bH          : {params['bH']}")
    print(f"Chosen bH_prime    : {params['bH_prime']}")

    if args.show_terms:
        print()
        print(format_beginner_terms())

    result = run_qds_protocol(
        document=args.document,
        bM=args.bits,
        bH=params["bH"],
        bH_prime=params["bH_prime"],
        verbose=not args.quiet,
    )

    print()
    print(format_result_summary(result))


if __name__ == "__main__":
    main()
