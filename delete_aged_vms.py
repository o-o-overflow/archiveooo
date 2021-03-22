#!/usr/bin/env python3
"""Instances auto-shutdown and auto-terminate on their own, but we want to make sure + delete the security group and internal objects"""

import argparse
import datetime
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
    import django.utils.timezone

    parser = argparse.ArgumentParser()
    parser.add_argument("--max-age", metavar='MINUTES', type=int, default=30, help="Default: 30 (minutes)")
    parser.add_argument("--study-max-age", metavar='MINUTES', type=int, default=55, help="Default: 55 (minutes)")
    parser.add_argument("--log-level", metavar='LEVEL', default="DEBUG", help="Default: DEBUG")

    args = parser.parse_args()

    if args.log_level:
        logger.setLevel(args.log_level)

    now = django.utils.timezone.now()
    max_dt = datetime.timedelta(minutes=args.max_age)
    study_max_dt = datetime.timedelta(minutes=args.study_max_age)


    # TODO: Also enumerate in Amazon, using separate credentials
    #       Tags?

    for vm in VM.objects.filter(deleted=False).all():
        dt = now - vm.creation_time
        desc = "study " if vm.study_opted_in else ""
        if dt < (study_max_dt if vm.study_opted_in else max_dt):
            logger.debug("Leaving young %sVM %s alone (age: %s)", desc, vm, dt)
            continue
        logger.debug("Deleting %sVM %s (age: %s)", desc, vm, dt)
        errcode, output = delete_ooo_vm(vm)
        if errcode == 0:
            logger.debug("Successfully deleted %s%s", desc, vm)
        else:
            logger.error("Error during deletion of %s%s: %s", desc, vm, output)


if __name__ == "__main__":
    sys.exit(main())
