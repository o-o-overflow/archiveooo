from django.conf import settings
from django.contrib.auth.models import User
from django.db import transaction
import ipaddress
import logging
import re
import boto3
from typing import Tuple, Optional
from .models import ChalCheckout, VM

logger = logging.getLogger("OOO")


USER_DATA_FMT="""
#cloud-config
repo_update: true
packages:
 - docker.io
runcmd:
 - [ sh, -c, "echo poweroff | at now + 25 minutes" ]
 - [ sh, -c, "date > /tmp/userdata_ran_at" ]
 - mkdir /root/.ssh
 - [ sh, -c, "echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAZg91lJwh6lhAdK3GmxVKJD/LPFbPRMGiqCtR7/YWhD jacopo precisa ed2' > /root/.ssh/authorized_keys" ]
 - [ sh, -c, "echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFfCTUJHvZeiPHp78ZrtT0T4KTLY5md3z0oebMrkJOjO chromebook_postcina' >> /root/.ssh/authorized_keys" ]
 - curl -sSL "{pingback_url}" -d "msg=Downloading the container..."
 - curl -sSL "{checkout.docker_image_tgzurl}" > /chal.tgz
 - curl -sSL "{pingback_url}" -d "msg=Setting up the network..."
 - [ bash, -c, "echo {my_ip} {my_domain_name} >> /etc/hosts" ]
 - iptables -A OUTPUT -m state --state ESTABLISHED -j ACCEPT
 - iptables -A OUTPUT -o lo -j ACCEPT
 - iptables -A OUTPUT -d "{my_ip_net}" -j ACCEPT
 - iptables -A OUTPUT -d "{player_ip}" -j ACCEPT
 - [ bash, -c, 'ip6tables -P INPUT DROP || true &>/dev/null' ]
 - [ bash, -c, 'ip6tables -P OUTPUT DROP || true &>/dev/null' ]
 - curl -sSL "{pingback_url}" -d "msg=Loading the container..."
 - adduser --disabled-password --disabled-login --gecos "" runner
 - adduser runner docker
 - su runner -c "docker load -i /chal.tgz"
 - curl -sSL "{pingback_url}" -d "msg=Starting the container..."
 - su runner -c "docker run -p {checkout.exposed_port}:{checkout.exposed_port} -d --name chal $(docker images -q|head -n1)"
 - curl -sSL "{pingback_url}" -d "msg=Finished, activated the final network settings."
 - iptables -D OUTPUT -d "{my_ip_net}" -j ACCEPT
"""
# ^^^ For simplicity, reduced to one IPv4 net for iptables
# TODO: docker won't work, need to restrict output iface only - iptables -P OUTPUT DROP

def get_ec2():
    # TODO: should it have its own credentials?
    p = settings.AWS_PROFILE
    avail = boto3.Session().available_profiles
    session = boto3.Session(profile_name=p if (p in avail) else None,
            region_name='us-west-2',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY)
    return session.resource("ec2")


# XXX: switched to single IPv4Network for simplicity
#def make_ip_ranges(nets) -> Dict[str,List[Dict[str,str]]]:
#    v4 = []; v6 = []
#    for n in nets:
#        if isinstance(n, ipaddress.IPv6Network):
#            v6.append({'CidrIpv6': str(n)})
#        elif isinstance(n, ipaddress.IPv4Network):
#            v4.append({'CidrIp': str(n)})
#        else:
#            if '/' not in str(n):
#                n = str(n) + '/32'
#            v4.append({'CidrIp': str(n)})
#    return {'IpRanges': v4, 'Ipv6Ranges': v6}

def make_ip_perms(net:ipaddress.IPv4Network, port:int=0):
    return {'FromPort': port if port else 0,
            'ToPort': port if port else 65535,
            'IpProtocol': 'tcp',
            'IpRanges': ({'CidrIp': str(net)},)}

def sg_name(vm: VM):
    return "archiveplayervm%d" % vm.id

def create_security_group(vm: VM, net: ipaddress.IPv4Network, ec2):
    # TODO: VPC default OK?
    assert re.match(r'\d+\.\d+\.\d+\.\d+\Z', settings.MY_IP4)
    me_net = ipaddress.IPv4Network(settings.MY_IP4 + "/32")

    sg = ec2.create_security_group(GroupName=sg_name(vm),
            Description="sg for archive.ooo player VM %s" % vm)
    logging.info("Created security group %s", sg.id)

    logging.warn("Leaving the default egress rule as-is")

    data = sg.authorize_ingress(IpPermissions=[
        make_ip_perms(net),
        make_ip_perms(me_net),
        ])
    logging.info("Ingress rules set for %s: %s", sg.id, data)
    assert data['ResponseMetadata']['HTTPStatusCode'] == 200

    # TODO: only if allow_egress? are connections tracked?
    data = sg.authorize_egress(IpPermissions=[
        make_ip_perms(net),
        make_ip_perms(me_net, port=443),
        ])
    logging.info("Egress rules set for %s: %s", sg.id, data)
    assert data['ResponseMetadata']['HTTPStatusCode'] == 200
    return sg


def spawn_ooo(checkout: ChalCheckout, net:ipaddress.IPv4Network, user:Optional[User],
        instant_cleanup=False) -> Tuple[Optional[str],Optional[str]]:
    """Returns vm.id, vm.uuid"""
    vm = None
    def _info(msg, *args, squared=' ', becomes_last=False):
        logger.info(msg.strip(), *args)
        m = f'[{squared}] ' + (msg % args) + "\n"
        if vm:
            with transaction.atomic():
                vm.messagelog += m + "\n"
                if becomes_last:
                    vm.latest_user_message = msg % args
                vm.save()
    def _progress(msg, *args, squared=' '):
        _info(msg, *args, squared=squared, becomes_last=True)
    def _act(msg, *args):
        _progress(msg, *args, squared='*')

    #def make_user_data():
    #    d = USER_DATA_FMT  # .format
    #    ret = b64encode(d.encode('utf-8', 'strict'))
    #    ret = gzip.compress(ret)
    #    assert len(ret) < 16*1024, "User data cannot be more than 16K"
    #    return ret


    ec2 = get_ec2()

    logger.info("Received request to spawn a container for %s", checkout)
    logger.info("Netmask allowed to connect: %s", net)

    sg = None
    instance = None
    try:
        vm = VM.objects.create(checkout=checkout, creation_user=user,
                flag=checkout.default_flag)
        vm.full_clean()
        vm.save()
        logger.info("Internal VM ID: %d", vm.id)

        _act("Creating the security group...")
        sg = create_security_group(vm, net, ec2)
        vm.security_group_id = sg.id
        vm.save()

        _act("Creating the VM...")
        plain_domain_name = settings.MY_DOMAIN_NAME
        if '@' in plain_domain_name:
            plain_domain_name = plain_domain_name.split('@')[1]
        instances = ec2.create_instances(
            SecurityGroupIds=[sg.id],
            UserData=USER_DATA_FMT.format(
                checkout=checkout,
                pingback_url=f"https://{settings.MY_DOMAIN_NAME}/vm_pingback/{vm.id}/{vm.pingback_uuid}/",
                my_ip_net=settings.MY_IP4+'/32',
                my_ip=settings.MY_IP4,
                my_domain_name=plain_domain_name,
                player_ip=str(net)),
            MaxCount=1, MinCount=1,
            ImageId='ami-005e54dee72cc1d00',  # Ubuntu 20.04
            InstanceType='t2.nano',

            KeyName='for_archive_player_vms',
            Monitoring={'Enabled':False},
            InstanceInitiatedShutdownBehavior='terminate',

            # CANNOT USE (won't have the keypair): MetadataOptions={'HttpEndpoint': 'disabled'},
            # TODO: set later?
            MetadataOptions={'HttpTokens': 'required'},
            # ClientToken
            # TagSpecifications=[{'Tags':[{'Key':'archivevm', 'Value':str(vm.id)}]}],
        )
        #LaunchTemplate={'LaunchTemplateName': 'archive_default'},
        # XXX: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Run_Instance_Idempotency.html

        assert len(instances) == 1
        instance = instances[0]
        vm.instance_id = instance.instance_id
        vm.save()

        _progress("VM spawned, please wait...")

        if instant_cleanup:
            _act("Instant cleanup")
            data = instance.terminate()
            assert data['ResponseMetadata']['HTTPStatusCode'] == 200
            _info("Waiting for the 'terminated' state...")
            instance.wait_until_terminated()
            _info("Deleting the security group (%s)", sg.id)
            sg.delete()
        return vm.id, vm.pingback_uuid

    except Exception:
        if settings.DEBUG:
            raise
        logger.exception("Got exception while creating the VM")
        if vm and instance:
            instance.terminate()
            instance.wait_until_terminated()
            vm.instance_id = None
        if sg:
            sg.delete()
        if vm:
            vm.messagelog += "\n\nThere was an error while creating the VM"
            vm.delete()
        return None, None


def delete_ooo_vm(vm:VM) -> Tuple[int,str]:
    all_output = "[ ] Deletion started...\n"
    try:
        ec2 = get_ec2()
        if vm.instance_id:
            all_output += "[*] Terminating the EC2 VM\n"
            instance = ec2.Instance(vm.instance_id)
            instance.terminate()
            all_output += "Waiting for the EC2 VM to terminate...\n"
            instance.wait_until_terminated()
            vm.instance_id = None

        if vm.security_group_id:
            all_output += "[*] Deleting the EC2 Security Group\n"
            sg = ec2.SecurityGroup(vm.security_group_id)
            sg.delete()

        all_output += "[_] Finished, deleting the internal VM object.\n"
        vm.delete()
        return 0, all_output
    except Exception as e:
        return 99, "Got exception %s %s" % (type(e), e)


def minimize_egress(vm: VM) -> bool:
    try:
        ec2 = get_ec2()
        assert vm.security_group_id
        sg = ec2.SecurityGroup(vm.security_group_id)

        ## XXX: Maybe it would be best to grant the Describe permission and remove by listing
        aws_builtin_default = {'IpProtocol': '-1', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
        me_net = ipaddress.IPv4Network(settings.MY_IP4 + "/32")
        data = sg.revoke_egress(IpPermissions=[
            aws_builtin_default,
            make_ip_perms(me_net),
        ])

        logging.info("Non-player egress rules removed for %s", sg.id)
        assert data['ResponseMetadata']['HTTPStatusCode'] == 200
        return True
    except:
        logger.exception("minimize_egress failed")
        return False


def update_vm_ip(vm:VM) -> None:
    if vm.ip:
        return
    ec2 = get_ec2()
    instance = ec2.Instance(vm.instance_id)
    if instance.public_ip_address:
        vm.ip = instance.public_ip_address
        vm.save()
