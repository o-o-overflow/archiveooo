# Sample settings, adapt this to your local deployment
# Many can also be set via env vars
#
# See settings.py


SECRET_KEY = None   # Use one of the many generation options

DEBUG = False


# If sending emails:
ADMINS = [ ('Admin', 'archive@localhost') ]
DEFAULT_FROM_EMAIL = 'archive@example.com'

# Default: local SQLite file
#DATABASES = {
#    'default': {
#        'ENGINE': 'django.db.backends.postgresql',
#        'NAME': 'archiveooo',
#        'USER': 'archiveooouser',
#        'PASSWORD': '',
#        'CONN_MAX_AGE': 600,
#    }
#}


# Optional. Create folders if not in use (see below).
S3_BUCKET=None    # "archive-ooo-public"


# These are used both to create VMs and to upload to S3
AWS_ACCESS_KEY_ID = None
AWS_SECRET_ACCESS_KEY = None


# Optionally, protect VM spawning with reCAPTCHA
RECAPTCHA_SITE_KEY=None
RECAPTCHA_SECRET_KEY=None


# Optionally, upload images to dockerhub too
DOCKERHUB_REPO = None           # 'archiveooo/pub'
DOCKERHUB_USERNAME = None       # 'archiveooouser'
DOCKERHUB_PASSWORD = None


# See settings.py for other values, most importantly:
#IMAGES_DOWNLOAD_ROOT = '/tmp/'

# These are used to allow the VM to pingback
# settings.py tries to auto-determine them, but it's probably best to configure them here
#MY_DOMAIN_NAME = 'archive.ooo'
#MY_IP4 = "1.2.3.4"
