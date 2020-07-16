# Common helpers and validators
# Especially for SSH keys 

from django.core.exceptions import ValidationError
import ipaddress
import os
import random
import re
import string
import subprocess
import tempfile


# XXX: switched to single IPv4 for simplicity in UI and iptables -- can put back in if wanted
#def get_ip_networks(txt: str):
#    """Split out into ip_networks"""
#    txt = txt.replace(',',' ').replace(';', ' ')
#    return tuple( (ipaddress.ip_network(s) if ('/' in s) else ipaddress.ip_network(s+'/32')) \
#            for s in txt.split() )
#
#def get_ip_networks_validator(txt: str) -> None:
#    try:
#        get_ip_networks(txt)
#    except Exception as e:
#        raise ValidationError("Wrong format for the IP address whitelist. Expecting subnets separated by spaces, commas, or semicolons. %(etype)s: %(e)s",
#                params={'e':e, 'etype':type(e)} )
def get_ip_networks_validator(txt: str) -> None:  # for old migrations
    pass


def get_user_ip(request) -> str:
    from ipware import get_client_ip
    client_ip, _ = get_client_ip(request)
    if not client_ip:
        return ""
    try:
        ipaddress.IPv4Address(str(client_ip))  # TODO: IPv6
    except:
        return ""
    return client_ip


def make_deploy_key_file(k:str) -> str:
    """Creates a temporary file, returns the name. Caller removes it when done."""
    # TODO: mkdtemp?
    with tempfile.NamedTemporaryFile('wb', prefix='mia_deploy_key_', delete=False) as tmpf:
        for l in k.splitlines():
            tmpf.write(l.encode('ascii','strict') + b"\n")
    return tmpf.name


def ssh_keys_validator(txt: str) -> None:
    for k in txt.splitlines():
        ssh_key_validator(k)
def ssh_private_key_validator(k: str) -> str:
    """Get the ssh key fingerprint, or raise a ValidationError"""
    return ssh_key_validator(k, private=True)
def ssh_key_validator(k: str, private:bool=False) -> str:
    """Get an ssh key's fingerprint, or raise a ValidationError"""
    if private:
        if not k.startswith('-----BEGIN OPENSSH PRIVATE KEY-----'):
            raise ValidationError("Doesn't begin like an OpenSSH private key")
        if not k.rstrip().endswith('-----END OPENSSH PRIVATE KEY-----'):
            raise ValidationError("Doesn't end like an OpenSSH private key")
    else:
        # Besides ssh-keygen, we must exclude authorized_keys options
        keytype = k.split()[0]
        if keytype not in (
                'ssh-rsa', 'ssh-ed25519',  # TODO: force ssh-rsa for old VMs?
                'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp512'):
            raise ValidationError("Invalid ssh key type: %(kt)s", params={'kt':keytype})
    deploy_key_file = None
    try:
        if private:
            deploy_key_file = make_deploy_key_file(k)
            k = subprocess.run(['ssh-keygen', '-y', '-f', deploy_key_file],
                    input=k, universal_newlines=True, timeout=3, check=True,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout
        p = subprocess.run(['ssh-keygen', '-l', '-f-'],
                input=k.strip(), universal_newlines=True, timeout=3, check=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return p.stdout
    except Exception as e:
        raise ValidationError("Invalid %(t)s key: [%(out)s]: %(kb)s",
                params={'out': (e.output.strip() if hasattr(e,'output') else str(e)),  # type: ignore[attr-defined]
                    'kb':k[:10], 't': ('private' if private else 'public')})
    finally:
        if deploy_key_file: os.unlink(deploy_key_file)



def service_port_validator(val: int) -> None:
    if val == 22:
        raise ValidationError("The ssh port (22) must remain available, challenges cannot use it.")
    if not (1 <= val <= 65535):
        raise ValidationError("Invalid value for the challenge TCP/UDP port: %(v)d.", params={'v':val})


def _clean_name_for_tags(s:str) -> str:
    return re.sub(r'[^a-zA-Z0-9-]+', '', s).lower()

def gen_pingback_uuid() -> str:
    """Must match django's urlpattern GET"""
    return "".join(random.choices(string.ascii_letters + string.digits, k=20))
