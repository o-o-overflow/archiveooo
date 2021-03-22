#!/usr/bin/env python3

import argparse
import logging
import os
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

    from ctfoood.importer import test_deployed
    from ctfoood.models import VM
    from django.contrib.auth.models import User

    parser = argparse.ArgumentParser()
    parser.add_argument("--log-level", metavar='LEVEL', default="DEBUG", help="Default: DEBUG")
    parser.add_argument("--healthcheck", action='store_true', help="Will just run tester healthcheck (ip) (port)")
    parser.add_argument("vm", metavar='VM_ID', help="Internal VM id")
    advanced = parser.add_argument_group('Advanced')
    advanced.add_argument("--user", help="Username (default: user with the lowest id)")

    args = parser.parse_args()

    if args.log_level:
        logger.setLevel(args.log_level)

    args = parser.parse_args()

    if args.log_level:
        logger.setLevel(args.log_level)
    if args.user:
        user = User.objects.get(username=args.user)
    else:
        user = User.objects.order_by('id')[0]
    assert user, "No user found with that name (if passed, otherwise the db may simply not have any user)"

    
    vm = VM.objects.get(id=args.vm)
    logger.debug("[ ] Making sure the VM has finished booting...")
    while 'finished' not in vm.latest_user_message.lower():
        vm.refresh_from_db()
        if logger.level <= logging.INFO:
            print(vm.latest_user_message, end="          \r")
        time.sleep(2)

    vm.refresh_from_db()
    ip = vm.ip
    port = vm.checkout.exposed_port
    logger.info("[ ] Ready to test VM %d  ( %s : %d )", vm.id, ip, port)

    errcode, output = test_deployed(vm, user=user,
            real_terminal=True, log_level=args.log_level, just_healthcheck=args.healthcheck)
    if errcode == 0:
        logger.info("test_deployed exited with 0, but check for warnings and errors above")
    else:
        logger.error("test_deployed failed (returned %d)", errcode)
    return errcode



if __name__ == "__main__":
    sys.exit(main())
