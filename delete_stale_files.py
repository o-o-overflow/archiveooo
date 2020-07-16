#!/usr/bin/env python3

import argparse
import datetime
import logging
import os
import sys
from typing import Dict, Any


#logging.basicConfig(level="WARNING")  # boto3 / urllib3 still show debug logs?
logger = logging.getLogger("OOO")
logger.setLevel("DEBUG")
try:
    import coloredlogs
    coloredlogs.install(logger=logger, level="DEBUG")
except ImportError:
    pass



def _get_s3():
    import boto3
    p = 'periodic'
    avail = boto3.Session().available_profiles
    session = boto3.Session(profile_name=p if (p in avail) else None)
    return session.resource("s3")



def cleanup_s3(basedir: str, known: Dict[str,Any], settings, delete:bool=False):
    s3 = _get_s3()
    bucket = s3.Bucket(settings.S3_BUCKET)
    if not basedir.endswith('/'):
        basedir += '/'

    found = set()
    for s in bucket.objects.filter(Prefix=basedir):
        if s.key in known:
            found.add(s.key)
        else:
            if delete:
                logger.debug("Deleting: %s", s.key)
                s.delete()
            else:
                logger.info("Dry run: would delete: %s", s.key)

    missing = set(known.keys()) - found
    if missing:
        logger.critical("Some files are missing!")
        for m in missing:
            logger.error("  %s", known[m])




def main():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'archiveooo.settings')
    import django
    django.setup()

    from ctfoood.models import PublicFile, ChalCheckout
    from django.conf import settings
    import django.utils.timezone

    parser = argparse.ArgumentParser()
    parser.add_argument("--log-level", metavar='LEVEL', default="DEBUG", help="Default: DEBUG")
    parser.add_argument("--actually-delete", action='store_true', help="Default: report only")

    args = parser.parse_args()

    if args.log_level:
        logger.setLevel(args.log_level)


    # 1. Public files
    KNOWN_PF_BASEDIR:str = '/public_files/'
    local_pf : Dict[str,PublicFile] = {}
    s3_pf : Dict[str,PublicFile] = {}
    for pf in PublicFile.objects.all():
        if pf.local_path:
            local_pf[pf.local_path] = pf
        else:
            ki = pf.url.find(KNOWN_PF_BASEDIR)
            reconstructed_s3key = pf.url[ki:].strip('/')
            s3_pf[reconstructed_s3key] = pf
    if os.path.exists(settings.PUBLIC_FILES_ROOT):
        # TODO
        logger.critical("Not implemented: cleanup of PUBLIC_FILES_ROOT")
    if settings.S3_BUCKET:
        cleanup_s3('public_files', s3_pf,
                settings=settings, delete=args.actually_delete)


    # 2. Docker images
    KNOWN_DOCKERIMG_BASEDIR:str = '/docker_images/'
    local_di : Dict[str,ChalCheckout] = {}
    s3_di : Dict[str,ChalCheckout] = {}
    for cc in ChalCheckout.objects.all():
        di_url = cc.docker_image_tgzurl
        if 'amazonaws' in di_url:
            ki = di_url.find(KNOWN_DOCKERIMG_BASEDIR)
            reconstructed_s3key = di_url[ki:].strip('/')
            s3_di[reconstructed_s3key] = cc
        else:
            local_di[cc.docker_image_tgzpath] = cc
    if os.path.exists(settings.IMAGES_DOWNLOAD_ROOT):
        # TODO
        logger.critical("Not implemented: cleanup of IMAGES_DOWNLOAD_ROOT")
    if settings.S3_BUCKET:
        cleanup_s3('docker_images', s3_di,
                settings=settings, delete=args.actually_delete)

if __name__ == "__main__":
    sys.exit(main())
