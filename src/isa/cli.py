import argparse
import json

from isa.benchmarks.undici_crlf import demo_witness


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="isa", description="injection-smt-analyzer")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("version", help="print version")

    p_analyze = sub.add_parser("analyze", help="run analyzer")
    p_analyze.add_argument(
        "--benchmark",
        required=True,
        choices=["undici_crlf"],
        help="Benchmark target (temporary; will expand)",
    )
    p_analyze.add_argument(
        "--rev",
        default="v5.8.0",
        help="Target revision/tag for witness metadata (default: v5.8.0)",
    )

    args = parser.parse_args(argv)

    if args.cmd == "version":
        print("0.0.1")
        return 0

    if args.cmd == "analyze":
        if args.benchmark == "undici_crlf":
            w = demo_witness(args.rev)
            print(json.dumps(w.to_dict(), indent=2, sort_keys=True))
            return 0

    raise AssertionError("unreachable")


if __name__ == "__main__":
    raise SystemExit(main())
