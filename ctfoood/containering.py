import logging
import subprocess
from django.conf import settings
from .models import ChalCheckout

logger = logging.getLogger("OOO")


def do_docker_login() -> None:
    dl = subprocess.run(['docker','logout'],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True)

    dl = subprocess.run(['docker','login','--password-stdin',
            '-u', settings.DOCKERHUB_USERNAME],
            input=settings.DOCKERHUB_PASSWORD,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True, check=True)
    logger.debug("docker login result: %s", dl.stdout)


def push_to_dockerhub(checkout: ChalCheckout, as_default:bool=False,
        existing_checkout:bool=False,
        real_terminal:bool=False) -> str:
    """Push to the pre-created repo on dockerhub. Returns the URI to pull from."""
    assert settings.DOCKERHUB_REPO

    if existing_checkout:
        raise NotImplementedError()

    tag = settings.DOCKERHUB_REPO + ':' + checkout.chal.name
    if not as_default:
        tag += '-' + checkout.id

    logging.debug("docker login...")
    do_docker_login()

    logging.debug("Tagging locally...")
    o = subprocess.check_output(['docker','tag', checkout.get_imgtag(), tag],
        universal_newlines=True, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    logger.debug("docker tag (imgtag) %s  ->  %s", tag, o)

    logging.debug("Pushing %s...", tag)
    if real_terminal:
        subprocess.check_call(['docker','push',tag],
            universal_newlines=True)
        logger.debug("docker pushed")
    else:
        o = subprocess.check_output(['docker','push',tag],
            universal_newlines=True, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        logger.debug("docker push %s  ->  %s", tag, o)

    subprocess.check_output(['docker','rmi',tag],
            universal_newlines=True, stdin=subprocess.DEVNULL)

    return tag
