#!/usr/bin/env python3

import argparse
import logging
import os
import sys


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

    from ctfoood.spawner import delete_ooo_vm
    from ctfoood.models import VM

    parser = argparse.ArgumentParser()
    parser.add_argument("--log-level", metavar='LEVEL', default="DEBUG", help="Default: DEBUG")
    parser.add_argument("vmid", type=int, metavar='VM_ID', help="ID of the internal VM object")

    args = parser.parse_args()

    if args.log_level:
        logger.setLevel(args.log_level)


    vm = VM.objects.get(id=args.vmid)
    errcode, output = delete_ooo_vm(vm)
    if errcode == 0:
        logger.info("Successfully deleted %s", vm)
        return 0
    else:
        logger.error("FAILED to delete %s: %s", vm, output)
        return 1


if __name__ == "__main__":
    sys.exit(main())
