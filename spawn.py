#!/usr/bin/env python3

import argparse
import ipaddress
import logging
import os
import socket
import sys
import time


#logging.basicConfig(level="WARNING")  # boto3 / urllib3 still show debug logs?
logger = logging.getLogger("OOO")
logger.setLevel("DEBUG")
try:
    import coloredlogs
    coloredlogs.install(logger=logger, level="DEBUG")
except ImportError:
    pass



def main():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'archiveooo.settings')
    import django
    django.setup()

    from ctfoood.spawner import spawn_ooo
    from ctfoood.importer import test_deployed
    from ctfoood.models import Chal, ChalCheckout, VM
    from django.contrib.auth.models import User


    parser = argparse.ArgumentParser()
    parser.add_argument("--collect-data", dest='collect_data', action='store_true', help="Will collect data for study")
    parser.add_argument("--wait", action='store_true', help="Wait for the VM to finish booting")
    parser.add_argument("--print-banner", action='store_true', help="Will connect to print the server banner")
    parser.add_argument("--test", action='store_true', help="Will run: tester test_deployed exploit (ip) (port)")
    parser.add_argument("--healthcheck", action='store_true', help="Will just run tester healthcheck (ip) (port)")
    parser.add_argument("--log-level", metavar='LEVEL', default="DEBUG", help="Default: DEBUG")
    parser.add_argument("what", metavar='WHAT', help="Either a numeric checkout ID or a challenge name (=> its latest checkout).")
    parser.add_argument("net", nargs='?', default="0.0.0.0/0", metavar="IP/mask", help="IPs allowed to connect")
    advanced = parser.add_argument_group('Advanced')
    advanced.add_argument("--user", help="Username (default: user with the lowest id)")
    advanced.add_argument("--instant-cleanup", action="store_true", help="Create and remove immediately")
    advanced.add_argument("--block-my-own-ip", action="store_true", help="Won't auto-add MY_IP4 to the allowlist")

    args = parser.parse_args()

    if args.log_level:
        logger.setLevel(args.log_level)
    
    if args.test or args.healthcheck or args.print_banner:
        args.wait = True

    if args.user:
        user = User.objects.get(username=args.user)
    else:
        user = User.objects.order_by('id')[0]
    assert user, "No user found with that name (if passed, otherwise the db may simply not have any user)"

    if args.what.isdigit():
        checkout_id = int(args.what)
    else:
        chal = Chal.objects.filter(name=args.what).first()
        assert chal, "'{}' is neither a challenge name nor an integer checkout ID".format(args.what)
        latest = chal.checkouts.order_by('-id').first()
        assert latest, "No checkouts found for Chal {} ({})".format(chal, latest)
        checkout_id = latest.id
        logger.debug("Spawning the latest checkout for %s: %s", chal, checkout_id)
    checkout = ChalCheckout.objects.get(id=checkout_id)

    if '/' not in args.net:
        args.net += '/32'
    args.net = ipaddress.IPv4Network(args.net)


    vmid, uuid = spawn_ooo(checkout,
            net=args.net,
            user=user,
            collect_data=args.collect_data,
            allow_archive_server_ip=not args.block_my_own_ip,
            instant_cleanup=args.instant_cleanup)

    if not vmid:
        print("Failed!", file=sys.stderr)
        return 1

    print(f"Success: spawned VM id={vmid} uuid={uuid}", file=sys.stderr)
    if not args.wait:
        return 0

    vm = VM.objects.get(id=vmid)
    logger.debug("Waiting for the VM to report it's finished booting...")
    time.sleep(5)
    while 'finished' not in vm.latest_user_message.lower():
        vm.refresh_from_db()
        if logger.level <= logging.INFO:
            print(vm.latest_user_message, end="          \r")
        time.sleep(2)

    vm.refresh_from_db()
    ip = vm.ip
    port = checkout.exposed_port
    logger.info("[+] Finished booting VM %d  -->  %s : %d", vm.id, ip, port)

    if args.print_banner:
        logger.debug("Connecting to get the server banner...")
        with socket.create_connection((ip, port), timeout=5) as c:
            c.settimeout(5)
            print(c.recv(1024).decode('utf-8', 'backslashreplace'))

    if not args.test and not args.healthcheck:
        return 0

    errcode, output = test_deployed(VM.objects.get(id=vmid), user=user,
            real_terminal=True, log_level=args.log_level, just_healthcheck=args.healthcheck)
    if errcode == 0:
        logger.info("test_deployed exited with 0, but check for warnings and errors above")
    else:
        logger.error("test_deployed failed (returned %d)", errcode)
    return errcode



if __name__ == "__main__":
    sys.exit(main())
