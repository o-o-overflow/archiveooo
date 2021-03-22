#!/usr/bin/env python3

UserData="""
#cloud-config
repo_update: true
packages:
 - docker.io
runcmd:
 - [ sh, -c, "echo poweroff | at now + 25 minutes" ]
 - docker run -d --privileged --name sf-collector -v /var/run/docker.sock:/host/var/run/docker.sock -v /dev:/host/dev -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro -v /mnt/data:/mnt/data -e INTERVAL=60 -e EXPORTER_ID=${1337} -e OUTPUT=/mnt/data/ -e FILTER="container.name!=sf-collector and container.name!=sf-exporter" --rm sysflowtelemetry/sf-collector
 - echo "rm -rf /mnt/data" | at now + 20 minutes
 - dmesg -c
"""


import argparse
import logging
import os
import time

logger = logging.getLogger("OOO")
logger.setLevel("DEBUG")
try:
    import coloredlogs
    coloredlogs.install(logger=logger, level="DEBUG")
except ImportError:
    pass




def get_ec2_instance_state(instance):
    try:
        instance = ec2.Instance(instance.id)
    except:
        return "error"
    return instance.state['Name']

# spawn an ec2 instance and install IBM sysflow on it, wait for it shut down, then return the Instance object
def spawn_ec2_with_sysflow():
    ubuntu_ami = find_ubuntu_ami()
    instance = ec2.create_instances(ImageId=ubuntu_ami, InstanceType='t2.micro', MaxCount=1, MinCount=1, UserData=UserData)[0]
    logger.debug("Instance %s created, waiting for it to start running...", instance.id)
    instance.wait_until_running()
    logger.debug("Instance %s is running, waiting for its (automatic) shutdown...", instance.id)
    while get_ec2_instance_state(instance) != "stopped":
        #logger.debug("Instance state: %s", get_ec2_instance_state(instance))
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
    image_name = "archiveooo_study_ami_" + creation_time
    image = instance.create_image(Name=image_name)
    image.wait_until_exists()
    image.create_tags(Tags=[{'Key': 'creation_time', 'Value': creation_time},
        {'Key': 'study_ami_autogen', 'Value': 'autogen'},])
    logger.debug("Waiting for the image (%s) to become available...", image.id)
    while get_ami_status(image) != "available":
        time.sleep(60)

def terminate_instance(instance):
    instance.terminate()
    instance.wait_until_terminated()

def get_my_amis():
    return ec2.images.filter(Owners=['self'],
        Filters=[{'Name':'tag-key','Values':['study_ami_autogen']}])

def delete_old_amis():
    # find the latest study ami
    latest_time = 0
    latest_image = None
    my_images = get_my_amis()
    for image in my_images:
        if image.tags == None:
            continue
        for tag in image.tags:
            if tag['Key'] == 'creation_time':
                if latest_time < int(tag['Value']):
                    latest_time = int(tag['Value'])
                    latest_image = image
    # delete all amis except latest one
    logger.debug("Deleting all images except for the latest (%s)", latest_image.id)
    assert latest_image
    for image in my_images:
        if image.id != latest_image.id:
            logger.debug("Deleting old auto-generated AMI %s", image.id)
            image.deregister()



if __name__ == "__main__":
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'archiveooo.settings')
    import django
    django.setup()

    from ctfoood.spawner import get_ec2, find_ubuntu_ami
    ec2 = get_ec2(profile='archiveooo_ami_creator')

    parser = argparse.ArgumentParser()
    parser.add_argument("--log-level", metavar='LEVEL', default="DEBUG", help="Default: DEBUG")
    args = parser.parse_args()
    if args.log_level:
        logger.setLevel(args.log_level)

    instance = spawn_ec2_with_sysflow()
    create_ami(instance)
    terminate_instance(instance)
    delete_old_amis()
