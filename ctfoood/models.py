from django.db import models
from django.contrib.auth.models import User, Group
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
import django.urls
import datetime
import os
import subprocess

DEFAULT_CACHE_TIME = datetime.timedelta(days=1)


from ctfoood.helpers import ssh_keys_validator, ssh_private_key_validator, \
        get_user_ip, \
        service_port_validator, \
        gen_pingback_uuid, \
        _clean_name_for_tags


# DB models for user settings, credentials, etc.

class APICredential(models.Model):
    """Saved credentials to AWS"""
    # TODO: name = models.CharField(max_length=100, unique_together='owner_group')
    id = models.AutoField(primary_key=True)
    owner_group = models.ForeignKey(Group, on_delete=models.CASCADE)
    aws_access_key_id = models.CharField('AWS access key ID', max_length=500)
    aws_secret_access_key = models.CharField('API access key secret', max_length=500)
    #extra_creation_json = models.TextField(blank=True, help_text="May be used to override the machine type, etc.")
    ssh_keys = models.TextField('SSH keys', blank=True, validators=[ssh_keys_validator],  # TODO: no blank? by name?
            help_text="authorized_keys that will be added to all VMs spawned with these credentials")
    def __str__(self):
        return f"{self.owner_group}'s AWS credentials [{self.id}]"
    class Meta:
        verbose_name = "API credential"


class UserSettings(models.Model):
    """Extra settings and data kept for each user"""
    user = models.OneToOneField(User, primary_key=True, on_delete=models.CASCADE)

    solved = models.ManyToManyField('Chal', blank=True, related_name="solved_by")
    achievements = models.ManyToManyField('Achievement', blank=True)

    hide_videos = models.BooleanField(default=False)

    default_credentials = models.ForeignKey(APICredential, blank=True, null=True, on_delete=models.SET_NULL) # TODO: default to an accessible one
    default_region = models.CharField(blank=True, max_length=30)  # TODO: choice? geolocate if None?
    default_allowed_ip = models.GenericIPAddressField(protocol='IPv4', blank=True, null=True)  # TODO: IPv6
    # TODO: pagination settings?

    # TODO[auto-pull]: github_token = models.TextField(max_length=50)

    def get_groups(self):
        return self.user.groups.all()
    def get_groups_string(self) -> str:
        return ' '.join(str(g) for g in self.get_groups())
    def get_email(self) -> str:
        return self.user.email

    def fill_default_region(self, request) -> str:
        return self.default_region if self.default_region else 'us-west-2'  # TODO: geolocate, per-provider
    def fill_default_allowed_ip(self, request) -> str:
        dyn = get_user_ip(request)
        return dyn if dyn else self.default_allowed_ip


    def clean(self):  # TODO: constraint too?
        if not self.default_credentials:
            return
        if not self.user.groups.filter(id=self.default_credentials.owner_group.id).exists():
            raise ValidationError("The user doesn't have access to those default credentials (valid groups: %(x)s)",
                    params={'x': self.get_groups_string()})
    def __str__(self):
        return f"Settings for {self.user}"

    class Meta:
        verbose_name = "user settings"
        verbose_name_plural = "user settings"

    def solved_chals(self):
        return Chal.objects.filter(public_checkout__isnull=False,
            solved_by=self).order_by('-format', 'name')
    def points(self):
        return sum(c.points for c in self.solved_chals())



# DB model for non-default VM settings
# TODO: feasible for these go in info.yml?
class VMSetup(models.Model):
    id = models.AutoField(primary_key=True)
    allow_player_docker = models.BooleanField(default=False,
            help_text="If set, spawn instructions will still be shown for players to do it on their own")
    machine_type = models.CharField(max_length=50)  # TODO: validate?
    replacement_user_script = models.TextField(blank=True)
    extra_user_script = models.TextField(blank=True)
    player_notice = models.TextField(blank=True, help_text="Player-visible notice")
    class Meta:
        verbose_name = "VM setup"
    def using_it(self):
        return list(self.chal_set.all()) + list(self.checkouts.all()) + list(self.vm_set.all())



# TODO: permissions (idea is Chal is editable by owner_user || owner_group || staff)


# DB models for challenges and their deployments

FORMAT_CHOICES = [  # TODO get from backend and/or models.IntegerChoiches
        ('dc2020f', "2020 Finals"),
        ('dc2020q', "2020 Quals"),
        ('dc2019f', "2019 Finals"),
        ('dc2019q', "2019 Quals"),
        ('dc2018f', "2018 Finals"),
        ('dc2018q', "2018 Quals"), ]
TYPE_CHOICES = [  # TODO get from backend and/or models.IntegerChoiches
        ('normal', "normal (jeopardy quals, a/d finals)"),
        ('king_of_the_hill', "King of the Hill"), ]
FLAG_MAX_LEN = 300


class Chal(models.Model):
    """Base challenge info. Checkouts add onto this."""
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100, unique=True,
            validators=[RegexValidator(regex='\A[0-9a-zA-Z_-]+\Z', message='Incorrect name despite the lax regex, check with ./tester.')])
    format = models.CharField(choices=FORMAT_CHOICES, max_length=10, help_text='Year / format')
    type = models.CharField(choices=TYPE_CHOICES, max_length=20, default='normal')

    clean_name_for_tags = models.CharField(max_length=100, blank=True, editable=False)  # Used to detect name conflicts from auto-grepped names, must not be edited

    public_checkout = models.OneToOneField('ChalCheckout', related_name="public_checkout_for",
            help_text="The main public checkout. If there is one, the challenge is considered public and can appear on the homepage.",
            on_delete=models.SET_NULL, blank=True, null=True)

    owner_user = models.ForeignKey(User, on_delete=models.CASCADE)
    owner_group = models.ForeignKey(Group, on_delete=models.CASCADE)

    vm_setup = models.ForeignKey(VMSetup, blank=True, null=True, on_delete=models.SET_NULL, verbose_name="VM setup",
            help_text="Override parts of the default VM setup")

    # Auto-pulling
    autopull_deploy_key = models.TextField(blank=True, validators=(ssh_private_key_validator,),
            help_text="Private SSH key -- upload the public one as a deploy key on github")
    autopull_url = models.CharField('autopull URL', blank=True, max_length=300, help_text="Argument to git clone")
    autopull_branch = models.CharField(blank=True, max_length=50, help_text="Override the remote default")

    # Extra fields beyond the info.yml (whose data is captured per-checkout)
    extra_description = models.TextField(blank=True, help_text="markdown, shown below the original description")
    extra_tags = models.ManyToManyField('Tag', blank=True, related_name='+')
    official_writeup_url = models.URLField('Official writeup URL', blank=True)
    source_url = models.URLField('Main source URL visible to players', blank=True)
    source_notice = models.CharField('Source notice', max_length=500, blank=True,
            help_text="Player-visible extra info. Unfiltered HTML.")
    ctftime_url = models.URLField('CTFtime URL', blank=True,
            help_text="CTFtime for that year - Event tasks and writeups - should be there")  # TODO: default to ctftime url for that format https://ctftime.org/event/762/tasks/
    yt_videoid = models.CharField('Youtube video id', max_length=20, blank=True,
            validators=[RegexValidator(regex=r"""\A[A-Za-z0-9_.()-]+\Z""", message='Just the YouTube video ID (?v=xxx)')])

    # Extra competition data
    points = models.PositiveIntegerField(default=0, help_text="Points awarded at the end of the game.")
    solves_n = models.PositiveSmallIntegerField(default=0, help_text="Number of solves during the game.")
    solves_url = models.URLField('solves data URL', blank=True)  # TODO: JSON as from the scoreboard

    pcaps_url = models.URLField('pcaps URL', blank=True, help_text="Link for players to download pcaps.") # TODO: replay pcaps
    pcaps_notice = models.CharField('pcaps notice', max_length=500, blank=True, help_text="Notice for players.")


    def clean(self):  # TODO: constraint too?
        if self.public_checkout and not self.public_checkout.public:
            raise ValidationError("The public_checkout must itself be public (set it in its admin page)")
        if self.public_checkout and self.public_checkout.chal != self:
            raise ValidationError("public_checkout's associated chal [%(p)s] != me [%(s)s]",
                    params={'p': self.public_checkout.chal, 's': self})
        if self._there_are_name_collision():
            raise ValidationError("The name (possibly cleaned-up for docker tagging) collides with another challenge's")

    def _there_are_name_collision(self):
        # Mainly because of docker rm -f / docker rmi at the end of do_autopull()
        # TODO: When is this safe to call?
        if not self.clean_name_for_tags:
            return False
        return Chal.objects.filter(clean_name_for_tags__icontains=self.clean_name_for_tags).exclude(pk=self.pk).exists() \
            or Chal.objects.filter(name__icontains=self.clean_name_for_tags).exclude(pk=self.pk).exists() \
            or Chal.objects.filter(clean_name_for_tags__icontains=self.name).exclude(pk=self.pk).exists() \
            or Chal.objects.filter(name__icontains=self.name).exclude(pk=self.pk).exists()


    def get_tags(self):
        t = self.extra_tags
        if self.public_checkout:
            t = t.union(self.public_checkout.tags.all())
        return t.distinct()

    def is_public(self) -> bool:
        return (self.public_checkout is not None)
    def was_solved_by(self, user) -> bool:
        return self.solved_by.filter(user=user).exists()
    def __str__(self):
        return f"{self.format}-{self.name}"
    def get_absolute_url(self):
        return django.urls.reverse('chalpage', args=[self.name])
    class Meta:
        ordering = ["format", "name"]
        indexes = [ models.Index(fields=('name','public_checkout')) ]

    def get_clean_name_for_tags(self) -> str:
        return _clean_name_for_tags(self.name)

    def has_private_access(self, user: User) -> bool:
        return (self.owner_user == user) or \
                (self.owner_group in user.groups.all())
    def get_deploy_key_fingerprint(self) -> str:
        return ssh_private_key_validator(self.autopull_deploy_key)
    def show_git_clone(self) -> str:
        if not self.autopull_url:
            return "# missing autopull_url :("
        return f'git clone [...] {self.autopull_url}' + \
                (f' -b {self.autopull_branch}' if self.autopull_branch else '') + \
                (("   # With deploy key "+self.get_deploy_key_fingerprint()) if self.autopull_deploy_key else '')
    # TODO
    def get_vm_type(self):
        return "SMOL"
    def get_vm_cost(self):
        return "SOME MONEY"

    # For the admin list
    def tags_str(self) -> str:
        return ' '.join(str(t) for t in self.get_tags())
    def owner_name(self) -> str:
        return self.owner_user.username
    def has_source_url(self) -> bool:
        return bool(self.source_url)
    def has_checkouts(self) -> bool:
        return self.checkouts.exists()
    def has_docker_img(self) -> bool:
        return self.checkouts.filter(docker_image_built=True).exists()



class ChalCheckout(models.Model):
    """Checkout, as in a "version" or commit from git. This is what gets deployed one or more times.
       They are not kept indefinitely -- but each is hardlinked to the previous to save space."""
    id = models.AutoField(primary_key=True)
    chal = models.ForeignKey(Chal, on_delete=models.CASCADE, related_name='checkouts')
    public = models.BooleanField(default=False, help_text='Publicly visible. Checkouts can be public independently of the base chal. <b style="color:red">Normally, this is the only field that should be edited for a checkout object.</b>')
    
    offline = models.BooleanField(default=False, help_text="No server-side VM.")
    vm_setup = models.ForeignKey(VMSetup, blank=True, null=True, on_delete=models.SET_NULL,
            related_name='checkouts', verbose_name="VM setup",
            help_text="Checkout-specific override of the default VM setup")

    # Record of creation-time info
    creation_time = models.DateTimeField(auto_now_add=True)
    creation_info = models.TextField(blank=True, help_text="Where/how we got the files (debug)")
    creation_user = models.ForeignKey(User, on_delete=models.CASCADE)
    ran_tester = models.BooleanField(default=False)
    ran_test_deployed = models.BooleanField(default=False)
    tester_output = models.TextField(blank=True)
    tester_gave_errors = models.BooleanField(default=False)
    tester_gave_warnings = models.BooleanField(default=False)
    docker_image_built = models.BooleanField(default=False)
    docker_image_tgzpath = models.CharField(blank=True, null=True, max_length=300, help_text="Local path to the docker-saved.tar.gz")
    docker_image_tgzurl = models.CharField(blank=True, max_length=300, help_text="URL to the docker-saved.tar.gz")
    docker_image_tgzsha256 = models.CharField('docker-saved.tar.gz SHA256', blank=True, max_length=64,
            validators=[RegexValidator(regex='\A[0-9a-f]{64}\Z', message='Must be lowercase sha256')])

    dockerhub_uri = models.CharField(max_length=400, blank=True)

    # Record of git info, if available
    commit_hash = models.CharField(max_length=56, blank=True,
            validators=[RegexValidator(regex='\A[0-9a-f]+\Z', message='Must be a git commit hash, lowercase')])
    dirty_tree = models.BooleanField(default=True)
    branch = models.CharField(max_length=50, blank=True, help_text="Non-default git branch")
    pull_url = models.CharField("pull URL", blank=True, max_length=300, help_text="Argument to git clone")
    via_autopull = models.BooleanField(default=False, editable=False)

    # Info persisted from info.yml (to generate the page and act even if no recent git clone happened)
    description = models.TextField(blank=True, help_text="markdown + linebreaks")
    authors = models.CharField(blank=True, max_length=500) # TODO: list of users? links?
    tags = models.ManyToManyField('Tag', blank=True)
    exposed_port = models.PositiveIntegerField(blank=True, null=True, validators=[service_port_validator])
    default_flag = models.CharField(max_length=FLAG_MAX_LEN)
    violates_flag_format = models.BooleanField(default=False)

    # To speed up operations, can keep files around for some time
    # TODO: periodic cleanup of code, docker images, maybe private checkouts themselves
    cache = models.CharField(max_length=260, help_text="Path to the last checkout", blank=True)
    cache_until = models.DateTimeField(blank=True, null=True)
    _now_plus_cache_time = None   # old


    def __str__(self):
        x = ""
        if self.commit_hash:
            x = " " + self.commit_hash[:7] + ("-dirty" if self.dirty_tree else "")
        t = self.creation_time.strftime(r'%Y-%m-%d %H:%M %Z')
        if t.endswith(' UTC'): t = t[:-4] + "z"
        return f"Checkout {self.id}, {self.chal.name}{x} [{t}]"
    def get_absolute_url(self):
        return f"{self.chal.get_absolute_url()}{self.id}/"
    def get_tags(self):
        return self.tags.union(self.chal.extra_tags.all()).distinct()
    def public_git_clone_cmd(self) -> str:
        # TODO: make closer to the real cmd
        if (self.chal.source_url.startswith('https://github.com/')) and not self.dirty_tree:
            return f'git clone {self.chal.source_url}' + \
                    (f' -b {self.branch}' if self.branch else '')
        return ""

    def get_imgtag(self) -> str:
        return "oooa-%s-%s:%d" % (self.chal.format, self.chal.get_clean_name_for_tags(), self.id)

    def get_vm_setup(self):
        return self.vm_setup if self.vm_setup else self.chal.vm_setup
    def get_vm_setup_notice(self) -> str:
        return self.get_vm_setup().player_notice

    def can_player_spawn_vm(self) -> bool:
        if not self.docker_image_built:  # TODO: eventually allow custom setups
            return False
        if self.get_vm_setup():
            return self.get_vm_setup().allow_player_docker
        return True
    def can_ooo_spawn_vm(self) -> bool:
        # TODO: notionally this would be true even with VM setups, and just be gated by container or script availability
        if not self.docker_image_built:  # TODO: eventually allow custom setups
            return False
        return not self.get_vm_setup()

    def clean(self, *args, **kwargs):
        if self.dockerhub_uri and not self.public:
            raise ValidationError("Our images on dockerhub are always public. Remove and edit manually if appropriate.")

    class Meta:
        ordering = ["-creation_time"]
        get_latest_by = '-creation_time'
        indexes = [ models.Index(fields=('chal','public')), ]  # creation_time ?


class VM(models.Model):
    """VM we created, with one deployed challenge"""
    id = models.AutoField(primary_key=True)
    checkout = models.ForeignKey(ChalCheckout, blank=True, null=True, on_delete=models.SET_NULL)
    ip = models.GenericIPAddressField('IP', blank=True, null=True, help_text="Null if not yet created")
    creation_time = models.DateTimeField(auto_now_add=True)
    creation_user = models.ForeignKey(User, on_delete=models.CASCADE)
    flag = models.CharField(max_length=FLAG_MAX_LEN, help_text="The flag that was deployed, randomly-generated if possible.")

    deleted = models.BooleanField(default=False)

    security_group_id = models.CharField(max_length=150, blank=True)
    instance_id = models.CharField(max_length=150, blank=True)

    pingback_uuid = models.CharField(max_length=20, blank=True, default=gen_pingback_uuid,
            help_text="Random unique value, used to identify pingbacks from the VM")
    pingback_received = models.BooleanField(default=False)
    messagelog = models.TextField(blank=True)

    latest_user_message = models.CharField(max_length=200, blank=True)

    # Record what was used
    credentials = models.ForeignKey(APICredential, on_delete=models.CASCADE,
            blank=True, null=True, help_text="Empty == OOO's base")
    vm_setup = models.ForeignKey(VMSetup, blank=True, null=True, on_delete=models.SET_NULL,
            verbose_name="VM setup")

    # TODO: liveness check?
    def __str__(self):
        return f"{self.ip}:{self.checkout.exposed_port} for {self.checkout.chal}, id {self.id}"
    class Meta:
        verbose_name = "VM"


# Extra stuff on challenge pages

class PublicFile(models.Model):
    # TODO: make unique by sha256 and filename, no more checkout link
    id = models.AutoField(primary_key=True)
    checkout = models.ForeignKey(ChalCheckout, blank=True, null=True,  # Not really expecting it to be NULL if in use
            on_delete=models.CASCADE, related_name='public_files')
    filename = models.CharField(max_length=255)  # TODO: need to validate in admin?
    local_path = models.CharField(max_length=500, blank=True, null=True)
    url = models.CharField('URL', max_length=300)
    sha256 = models.CharField('SHA256', blank=True, max_length=64,
            validators=[RegexValidator(regex='\A[0-9a-f]{64}\Z', message='Must be lowercase sha256')])
    def __str__(self):
        return f"Public file {self.filename} for {self.checkout}"
    class Meta:
        unique_together = (('checkout','filename'),)
        order_with_respect_to = 'checkout'
    def post_delete(self, *args, **kwargs):
        try:
            os.unlink(self.local_path)
            subprocess.call(['rmdir', '--ignore-fail-on-non-empty', '--parents', os.path.dirname(self.local_path)])
        except Exception:
            pass
        super().post_delete(*args, **kwargs)
    def delete(self, *args, **kwargs):
        try:
            os.unlink(self.local_path)
            subprocess.call(['rmdir', '--ignore-fail-on-non-empty', '--parents', os.path.dirname(self.local_path)])
        except Exception:
            pass
        super().delete(*args, **kwargs)


class Hint(models.Model):
    id = models.AutoField(primary_key=True)
    chal = models.ForeignKey(Chal, on_delete=models.CASCADE, related_name='hints')
    text = models.CharField(max_length=500)
    def __str__(self):
        return self.text
    class Meta:
        order_with_respect_to = 'chal'
class SpoileredNote(models.Model):
    id = models.AutoField(primary_key=True)
    chal = models.ForeignKey(Chal, on_delete=models.CASCADE, related_name='spoilered_notes')
    name = models.CharField(max_length=100, help_text="Shown next to the arrow that opens the spoiler.")
    text = models.CharField(max_length=500)
    def __str__(self):
        return self.text
    class Meta:
        order_with_respect_to = 'chal'


# TODO: taggit?
class Tag(models.Model):
    name = models.CharField(max_length=20, primary_key=True)
    def __str__(self):
        return self.name


class Achievement(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=300, unique=True)
    how = models.CharField(max_length=300)
    text = models.TextField(blank=True, help_text="For now, just shown as tooltip.")

    tag = models.ForeignKey(Tag, blank=True, null=True, on_delete=models.SET_NULL,
            help_text="Achievement auto-granted once all those challenges are solved.")
    points = models.PositiveSmallIntegerField(default=0,
            help_text="Achievement auto-granted at that point-sum.")

    # TODO: code = 
    def __str__(self):
        return self.name
    class Meta:
        ordering = ['name']
    def clean(self):
        if self.tag and self.points:
            raise ValidationError("There should be only one auto-assignment system")  # it would be an OR right now
