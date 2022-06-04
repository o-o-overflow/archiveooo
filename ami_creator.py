#!/usr/bin/env python3

UserData="""
#cloud-config
repo_update: true
packages:
 - docker.io
 - awscli
runcmd:
 - [ sh, -c, "echo poweroff | at now + 25 minutes" ]
 - docker run -d --privileged --name sf-collector -v /var/run/docker.sock:/host/var/run/docker.sock -v /dev:/host/dev -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro -v /mnt/data:/mnt/data -e INTERVAL=60 -e EXPORTER_ID=${1337} -e OUTPUT=/mnt/data/ -e FILTER="container.name!=sf-collector and container.name!=sf-exporter and container.type!=host" --rm sysflowtelemetry/sf-collector:0.3.1
 - echo "rm -rf /mnt/data" | at now + 20 minutes
 - dmesg -c
"""


import argparse
import logging
import os
import datetime
import time
import sys

logger = logging.getLogger("OOO")
logger.setLevel("DEBUG")
try:
    import coloredlogs
    coloredlogs.install(logger=logger, level="DEBUG")
except ImportError:
    pass


SECURITY_GROUP_NAME = "ami_creator_vm_sg"
#security_group_id


# XXX: the userscript may get stuck, unclear why (even seen auto-reboots instead of shutdowns!)
#      give up if this much time has passed before the VM stops itself
MAX_STOP_TIME_SECONDS = 60*60*2



def get_ec2_instance_state(instance):
    try:
        instance = ec2.Instance(instance.id)
    except:
        return "error"
    return instance.state['Name']

# spawn an ec2 instance and install IBM sysflow on it, wait for it shut down, then return the Instance object
def spawn_ec2_with_sysflow():
    ubuntu_ami = find_ubuntu_ami()
    # Security group so we can ssh-in in case of issues
    sg = ec2.create_security_group(GroupName=SECURITY_GROUP_NAME,
            Description="security group that allows us to ssh into the VM spawned by ami_creator.py")
    global security_group_id
    security_group_id = sg.id
    response = sg.authorize_ingress(IpPermissions=[
        {'FromPort': 22, 'ToPort': 22, 'IpProtocol': 'tcp',
         'IpRanges': ({'CidrIp': '0.0.0.0/0'},)}
        ])
    assert response['ResponseMetadata']['HTTPStatusCode'] == 200
    # Create the VM and wait for it to auto-terminate (see the UserData)
    instance = ec2.create_instances(ImageId=ubuntu_ami, InstanceType='t2.micro', MaxCount=1, MinCount=1, UserData=UserData, KeyName=settings.AWS_KEYPAIR_NAME, SecurityGroupIds=[sg.id])[0]
    logger.debug("Instance %s created, waiting for it to start running...", instance.id)
    instance.wait_until_running()
    logger.debug("Instance %s is running, waiting for its (automatic) shutdown...", instance.id)

    # XXX: WTF THIS CAN BE RUNNING FOREVER, UNCLEAR WHY THE USERSCRIPT DOESN'T COMPLETE -> TIMEOUT AND KILL INSTANCE?
    start_time = time.time()
    while get_ec2_instance_state(instance) != "stopped":
        elapsed = time.time() - start_time
        if elapsed > MAX_STOP_TIME_SECONDS:
            logger.critical("WTF, instance state = %s != stopped after %d seconds = %d minutes!", get_ec2_instance_state(instance), elapsed, elapsed // 60)
            terminate_instance(instance)
            logger.critical("Something went wrong in spawning instance %s, I destroyed it and cleaned up BUT MUST RUN AGAIN!", instance)
            return None
        logger.debug("Instance state: %s (running for %d seconds)", get_ec2_instance_state(instance), elapsed)
        time.sleep(60)
    return ec2.Instance(instance.id)

def get_ami_status(image):
    try:
        image = ec2.Image(image.id)
    except:
        raise  # I prefer to get alerted by cron [Jacopo]
        #return "error"
    return image.state

# create ami for spawning containers with study permission
def create_ami(instance):
    logger.debug("Creating the ami from instance %s...", instance)
    creation_time = str(int(time.time()))
    creation_time_human = datetime.datetime.utcfromtimestamp(int(creation_time)).isoformat()
    image_name = "archiveooo_study_ami_" + creation_time
    image = instance.create_image(Name=image_name)
    image.wait_until_exists()
    logger.debug("Waiting for the image (%s) to become available...", image.id)
    while get_ami_status(image) != "available":
        time.sleep(60)
    image.create_tags(Tags=[{'Key': 'creation_time', 'Value': creation_time},
        {'Key': 'creation_time_human', 'Value': creation_time_human},
        {'Key': 'study_ami_autogen', 'Value': 'autogen'},])

def terminate_instance(instance):
    logger.debug("Terminating instance %s ...", instance)
    instance.terminate()
    instance.wait_until_terminated()
    logger.debug("Instance %s terminated, deleting security group...", instance)
    sg = ec2.SecurityGroup(security_group_id)
    sg.delete()
    logger.debug("Security group %s deleted", security_group_id)


def delete_old_amis():
    # delete all amis except latest one
    latest_image_id = find_study_ami(ec2)
    logger.debug("Deleting all images except for the latest (%s)", latest_image_id)
    assert latest_image_id
    for image in get_study_amis(ec2):
        if image.id != latest_image_id:
            logger.debug("Deleting old auto-generated AMI %s", image.id)
            image.deregister()



if __name__ == "__main__":
    exit_code = 88

    MY_LOCK_FILE = '/run/lock/ami_creator_active.lock'
    if os.path.exists(MY_LOCK_FILE): os.system("echo '#### LOCK FILE EXISTED, IT SAYS:  #####'; cat " + MY_LOCK_FILE + "; echo; echo") # Just for debugging
    with open(MY_LOCK_FILE, 'x') as lf:
        lf.write("Started at: {}\nPID: {}\nPPID: {}\n".format(time.asctime(), os.getpid(), os.getppid()))

    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'archiveooo.settings')
    import django
    django.setup()
    from django.conf import settings

    from ctfoood.spawner import get_ec2, find_ubuntu_ami, find_study_ami, get_study_amis
    ec2 = get_ec2(profile='archiveooo_ami_creator')

    parser = argparse.ArgumentParser()
    parser.add_argument("--log-level", metavar='LEVEL', default="DEBUG", help="Default: DEBUG")
    parser.add_argument("--from-this-stopped-instance", metavar='INSTANCE_ID')
    args = parser.parse_args()
    if args.log_level:
        logger.setLevel(args.log_level)

    if args.from_this_stopped_instance:
        instance = ec2.Instance(id=args.from_this_stopped_instance)
    else:
        instance = spawn_ec2_with_sysflow()

    if instance is not None:
        create_ami(instance)
        terminate_instance(instance)
        delete_old_amis()
        exit_code = 0
    else:
        logger.error("TERMINATING WITH ERROR, MUST RUN AGAIN!")
        # TODO: also schedule re-running in 1 day?
        exit_code = 46

    os.unlink(MY_LOCK_FILE)
    logger.info("Finished, exiting with code %d", exit_code)
    sys.exit(exit_code)
