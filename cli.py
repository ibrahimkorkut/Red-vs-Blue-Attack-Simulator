import argparse

from core.config import Config
from core.logging import setup_logging
from agents.red_agent import RedAgent
from agents.blue_agent import BlueAgent
from modules import port_scanner, web_scanner
from core.ml import MLAnomalyEngine


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "CyberSecurity Research Lab Platform "
            "(defensive, simulation-only, non-destructive)."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Red simulation
    sim_parser = subparsers.add_parser(
        "simulate", help="Run synthetic attack simulations (logs only)."
    )
    sim_parser.add_argument(
        "--scenario",
        required=True,
        choices=[
            "brute_force",
            "credential_stuffing",
            "port_scan",
            "web_injection",
            "wifi_deauth",
        ],
        help="Simulation scenario to run (synthetic, no real attacks).",
    )
    sim_parser.add_argument(
        "--count",
        type=int,
        default=100,
        help="Number of synthetic events to generate.",
    )

    # Blue analysis
    analyze_parser = subparsers.add_parser(
        "analyze-logs", help="Analyze logs with the Blue Defense Agent."
    )
    analyze_parser.add_argument(
        "--input",
        required=True,
        help="Path to a JSONL log file or directory of JSONL files.",
    )
    analyze_parser.add_argument(
        "--output",
        required=True,
        help="Base path (without extension) for JSON and HTML reports.",
    )

    # Defensive scanners
    port_parser = subparsers.add_parser(
        "scan-ports", help="Run safe TCP connect port scan (defensive assessment only)."
    )
    port_parser.add_argument("--target", required=True, help="Target host/IP.")
    port_parser.add_argument(
        "--ports",
        required=True,
        help="Port specification, e.g. 1-1024 or 80,443,8080",
    )

    web_parser = subparsers.add_parser(
        "scan-web", help="Run non-destructive same-domain web security scan."
    )
    web_parser.add_argument("--url", required=True, help="Root URL to scan.")

    # ML anomaly
    ml_parser = subparsers.add_parser(
        "train-ml", help="Train Isolation Forest / clustering on log datasets."
    )
    ml_parser.add_argument(
        "--dataset", required=True, help="Path to normalized JSONL log dataset."
    )
    ml_parser.add_argument(
        "--model-out", required=True, help="Path to save the trained ML model."
    )

    args = parser.parse_args()

    cfg = Config.from_file("config.yaml")
    logger = setup_logging(cfg)

    if args.command == "simulate":
        red = RedAgent(cfg, logger)
        red.run_scenario(args.scenario, count=args.count)

    elif args.command == "analyze-logs":
        blue = BlueAgent(cfg, logger)
        blue.analyze_logs(args.input, output_base=args.output)

    elif args.command == "scan-ports":
        port_scanner.safe_tcp_scan(cfg, logger, args.target, args.ports)

    elif args.command == "scan-web":
        web_scanner.scan_site(cfg, logger, args.url)

    elif args.command == "train-ml":
        engine = MLAnomalyEngine(cfg, logger)
        engine.train_from_logs(args.dataset, args.model_out)


if __name__ == "__main__":
    main()

