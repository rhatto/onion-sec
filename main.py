import logging
import argparse
import json
import dataclasses
import onion_sec


def main():
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser()
    parser.add_argument('domain')
    parser.add_argument('--proxy_addr', default="localhost")
    parser.add_argument('--proxy_port', default=9050, type=int)
    parser.add_argument('--control_port', default=9051, type=int)
    args = parser.parse_args()

    onion_sec = onion_sec.OnionSec(args.proxy_addr, args.proxy_port, args.control_port)
    print(json.dumps(
        dataclasses.asdict(onion_sec.run_report(args.domain)),
        indent=2,
    ))


if __name__ == '__main__':
    main()
