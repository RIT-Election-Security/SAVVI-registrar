#!/usr/bin/env python3

import sys
import os
import json
import argparse
import socket
import requests
import logging


def parse_args():
    parser = argparse.ArgumentParser(
        description='Register sensor to CHN server')
    parser.add_argument('-p',
                        '--honeypot',
                        help='Type of honeypot for this sensor',
                        required=True)
    parser.add_argument('-d',
                        '--deploy-key',
                        help='Deploy Key for registration',
                        required=True)
    parser.add_argument('-n',
                        '--hostname',
                        help='Hostname of honeypot',
                        default=socket.gethostname())
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
    except Exception as e:
        local_ip = '127.0.0.1'
    parser.add_argument('-i',
                        '--ip-address',
                        help='IP of honeypot',
                        default=local_ip)
    parser.add_argument('-u',
                        '--url',
                        help='CHN Server to register to',
                        required=True)
    parser.add_argument('-k',
                        '--no-verify',
                        help='Do not verify TLS connection',
                        action='store_true')
    parser.add_argument('-o',
                        '--state-output',
                        help='State output file',
                        type=str)

    return parser.parse_args()


def main():

    args = parse_args()
    name = "%s-%s" % (args.hostname, args.honeypot)
    overwrite = False
    if os.path.exists(args.state_output):
        logging.debug("Registration file exists, making sure it's valid")
        try:
            with open(args.state_output, 'r') as state:
                data = state.read().strip()
                existing_data = json.loads("%s" % data)
        except Exception as e:
            logging.error(
                "Could not decode state file in to json, overwriting it")
            logging.error("%s" % e)
            overwrite = True
            existing_data = None

        if existing_data:
            if 'honeypot' not in existing_data:
                logging.error(
                    "State file does not include honeypot, overwriting")
                overwrite = True
    else:
        overwrite = True

    if not overwrite:
        logging.warning("Registration completed prior to this run")
        return 0

    resp = requests.post("%s/api/sensor/" % args.url,
                         headers={"Content-Type": "application/json"},
                         json={
                             "name": name,
                             "deploy_key": args.deploy_key,
                             "hostname": args.hostname,
                             "ip": args.ip_address,
                             "honeypot": args.honeypot,
                         },
                         verify=not args.no_verify)
    try:
        resp.raise_for_status()
    except Exception as e:
        logging.error("Could not register client ☹️")
        logging.error("%s" % e)
        return 5

    with open(args.state_output, 'w') as state:
        state.write(json.dumps(resp.json()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
