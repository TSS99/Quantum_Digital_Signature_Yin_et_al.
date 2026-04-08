from qds_beginner import compute_security_params, run_qds_protocol


def main() -> None:
    document = "Hello, QDS!"
    bM = 500
    epsilon_target = 1e-10

    params = compute_security_params(bM, epsilon_target)

    print("Quantum Digital Signature beginner demo")
    print("=" * 45)
    print(f"Document           : {document}")
    print(f"Document size (bM) : {bM}")
    print(f"Target epsilon     : {epsilon_target:.1e}")
    print(f"Chosen bH          : {params['bH']}")
    print(f"Chosen bH_prime    : {params['bH_prime']}")
    print()

    result = run_qds_protocol(
        document=document,
        bM=bM,
        bH=params["bH"],
        bH_prime=params["bH_prime"],
        verbose=True,
    )

    print("\nSummary")
    print("-" * 45)
    print(f"Protocol success : {result['success']}")
    print(f"Bob accepted     : {result['bob_accept']}")
    print(f"Charlie accepted : {result['charlie_accept']}")
    print(f"Agreement        : {result['agreement']}")
    print(f"lS               : {result['lS']} bits")
    print(f"lP               : {result['lP']} bits")


if __name__ == "__main__":
    main()
