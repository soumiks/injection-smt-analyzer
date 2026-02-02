import argparse


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="isa", description="injection-smt-analyzer")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("version", help="print version")

    args = parser.parse_args(argv)

    if args.cmd == "version":
        print("0.0.1")
        return 0

    raise AssertionError("unreachable")
