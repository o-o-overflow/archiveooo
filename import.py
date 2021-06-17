#!/usr/bin/env python3

import argparse
import logging
import os
import re
import subprocess
import sys
from urllib.request import urlopen


#logging.basicConfig(level="WARNING")  # boto3 / urllib3 still show debug logs?
logger = logging.getLogger("OOO")
logger.setLevel("DEBUG")
try:
    import coloredlogs
    coloredlogs.install(logger=logger, level="DEBUG")
except ImportError:
    pass



def is_url_valid(url):
    try:
        with urlopen(url) as u:
            assert u.getcode() == 200
            return True
    except Exception as e:
        logger.debug("Tried URL %s -- not valid (%s %s)", url, type(e), str(e))
        return False


def main():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'archiveooo.settings')
    import django
    django.setup()

    from ctfoood.importer import do_autopull
    from ctfoood.models import Chal
    from django.contrib.auth.models import User, Group
    from django.core.exceptions import ValidationError


    parser = argparse.ArgumentParser(description="Challenge dir or git -> ChalCheckout."
            "Runs ./tester build. Will also use a deployment key if stored in the db.",
            epilog=f"Example: {sys.argv[0]} know_your_mem git@github.com:Jacopo/know_your_mem_private_fixed.git")
    parser.add_argument("--create-chal", action='store_true', help="Auto-create the base Chal object if not found")
    parser.add_argument("--run-tester", action='store_true' ,help="Do a full ./tester run")
    parser.add_argument("--public", action='store_true', help="Immediately mark the checkout as public (not the chal)")
    parser.add_argument("--as-default", action='store_true', help="This immediately becomes the new public checkout.")
    parser.add_argument("--dockerhub", action='store_true', help="Push to dockerhub, potentially as the new default")
    parser.add_argument("chalname", help="Name of the challenge (without the year prefix). Optional for --create-chal")
    parser.add_argument("pull_from", nargs='?', help="Argument to git clone")
    advanced = parser.add_argument_group('Advanced')
    advanced.add_argument("--log-level", metavar='LEVEL', default="DEBUG", help="Default: DEBUG")
    advanced.add_argument("--branch", help="Override the default branch")
    advanced.add_argument("--user", help="Username (default: user with the lowest id)")
    advanced.add_argument("--group", help="Group name (default: the user's), only for --create-chal")
    advanced.add_argument("--no-cleanup", action="store_true", help="Would normally cleanup by grepping 'docker ps' and 'docker images' for the challenge name")
    advanced.add_argument("--submodules", metavar="yes/no", choices=('yes','no'), help="Override the default")
    forcreatechal = parser.add_argument_group('For --create-chal')
    forcreatechal.add_argument("--format", help="Only used with --create-chal (default: reads it from the git url)")
    forcreatechal.add_argument("--accept-unclean", action="store_true", help="Would normally reject name collisions and the like -- but it's fine if we're sure we're importing only one challenge at a time")

    args = parser.parse_args()

    if args.log_level:
        logger.setLevel(args.log_level)

    assert not args.dockerhub or args.public, "--dockerhub goes together with --public"
    assert not args.as_default or args.public, "--as-default goes together with --public"

    if args.user:
        user = User.objects.get(username=args.user)
    else:
        user = User.objects.order_by('id')[0]
    assert user, "No user found with that name (if passed, otherwise the db may simply not have any user)"
    group = None
    if args.group:
        group = Group.objects.get(groupname=args.group)
        assert group, "No group found with that name"
    else:
        assert user.groups, "User {} is not in any group, and right now we need one. Just create a group and add {} to it.".format(user,user)  # TODO: auto-create?
        group = user.groups.order_by('id')[0]

    submodules = args.submodules
    if submodules is not None:
        submodules = (submodules == 'yes')
    assert submodules is None or submodules is True or submodules is False



    chal_already_exists = Chal.objects.filter(name=args.chalname).exists()
    if args.create_chal and not chal_already_exists:
        if not args.pull_from:
            # Allows passing the URL only
            if ':' not in args.chalname:
                logger.critical("You didn't specify a URL to pull from, and '%s' didn't look like one either. Pass both the name and the URL if you want to use it.", args.chalname)
                sys.exit(2)
            args.pull_from = args.chalname
            args.chalname = subprocess.check_output(["basename",args.pull_from], universal_newlines=True).strip()
            if args.chalname.endswith('.git'):
                args.chalname = args.chalname[:-4]
            fm = re.match(r'dc[0-9]+[qf]-(.*)', args.chalname)
            if fm:
                args.chalname = fm[1]
            logger.info("Auto-deduced the challenge name: %s", args.chalname)
        y = args.format
        if not y:
            myear = re.search(r'dc[0-9]+[qf]', args.pull_from)
            assert myear, "Expecting dcYYYY[qf] in the challenge URL to determine the format"
            y = myear.group(0)
        assert y in ('dc2018q', 'dc2018f', 'dc2019q', 'dc2019f', 'dc2020q', 'dc2020f', 'dc2021q', 'dc2021f')

        if y == 'dc2018q': solves_url = "https://scoreboard2018.oooverflow.io/#/solves"
        elif y == 'dc2018f': solves_url = "https://oooverflow.io/dc-ctf-2018-finals/"
        elif y == 'dc2019q': solves_url = "https://scoreboard2019.oooverflow.io/#/solves"
        elif y == 'dc2019f': solves_url = "https://oooverflow.io/dc-ctf-2019-finals/#game-data"
        elif y == 'dc2020q': solves_url = "https://scoreboard2020.oooverflow.io/#/solves"
        elif y == 'dc2020f': solves_url = "https://oooverflow.io/dc-ctf-2020-finals/#game-data"
        elif y == 'dc2021q': solves_url = "https://scoreboard.ooo/#/solves"
        elif y == 'dc2021f': solves_url = "https://oooverflow.io/dc-ctf-2021-finals/#game-data"
        else: solves_url = ""

        source_url = f"https://github.com/o-o-overflow/{y}-{args.chalname}"
        source_url_public = source_url + "-public"
        logger.debug("Checking if there's a separate public repo...")
        if is_url_valid(source_url_public):
            source_url = source_url_public
        if not is_url_valid(source_url):
            source_url = ""
            logger.info("No auto-created public source URL was valid for %s (players will get no link)", args.chalname)
        else:
            logger.debug("Public source URL set to: %s (players will get this link)", source_url)

        chal = Chal.objects.create(name=args.chalname, format=y, type='normal',
                owner_user=user, owner_group=group, autopull_url=args.pull_from,
                autopull_branch=args.branch if args.branch else "",
                autopull_submodules=submodules,
                source_url=source_url, solves_url=solves_url)
        try:
            chal.full_clean()
        except ValidationError as e:
            if not args.accept_unclean:
                logger.critical("The chal object for %s didn't pass full_clean(): %s "
                        "Not saving it. If it's just a name collision, and you're doing only one challenge, pass --accept-unclean",
                        chal.name, e.messages)
                sys.exit(4)
            logger.warning("Letting un-clean chal '%s' pass "
                    "(if it's a name collision, just make sure you're not doing two challenges at the same time): %s %s",
                    chal.name, type(e), e)
        chal.save()
    elif chal_already_exists:
        logger.debug("Challenge already exists, skipping creation")
    else:
        logger.critical("No chal with that name (%s) found -- do not pass the dcxxxx prefix", args.chalname)
        sys.exit(2)

    chal = Chal.objects.get(name=args.chalname)


    errcode, output, checkout = do_autopull(chal=chal, user=user, run_tester=args.run_tester,
            pull_from=args.pull_from, pull_branch=args.branch,
            is_autopull=False, real_terminal=True,
            tester_log_level=args.log_level,
            docker_cleanup=not args.no_cleanup, make_public=args.public,
            as_default=args.as_default, dockerhub=args.dockerhub,
            submodules=submodules)


    #print(output)
    if checkout:
        logger.info("[import.py summary] Checkout object created: %s -> http://127.0.0.1/%s", str(checkout), checkout.get_absolute_url())
        if checkout.tester_gave_errors:
            logger.error("The tester reported errors (see above or in the admin page)")
        if checkout.tester_gave_warnings:
            logger.warning("The tester reported warnings (see above or in the admin page)")
    if errcode != 0:
        logger.critical("FAILED, errcode %d", errcode)
    return errcode



if __name__ == "__main__":
    sys.exit(main())
