#### Django + archive settings.
#### You should not modify this file, but rather override using local_settings_outside_git.py



import logging
import os
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# These are used for pingbacks from the VMs.
import subprocess
MY_DOMAIN_NAME = subprocess.check_output('hostname --fqdn',
        shell=True, universal_newlines=True).strip()
MY_IP4 = subprocess.check_output('dig -4 +short @8.8.8.8 "$(hostname --fqdn)"',
        shell=True, universal_newlines=True).strip()


# Optionally, upload public files and docker images to s3
S3_BUCKET = None

# Used both to spawn VMs and to access S3
AWS_PROFILE = None
AWS_ACCESS_KEY_ID = None
AWS_SECRET_ACCESS_KEY = None

AWS_REGION = 'us-west-2'  # VMs are spawned in this region. The IAM account can be limited to access this region only.

AWS_KEYPAIR_NAME = 'for_archive_player_vms' # Must be set up in AWS for that region
SSH_EXTRA_ROOT_ACCESS_KEY_FOR_VMS = ''      # Will also add this to /root/.ssh/authorized_keys



# Study settings
STUDY_METADATA_PATH = None
S3_BUCKET_STUDY = None
AWS_ACCESS_KEY_ID_STUDY = None
AWS_SECRET_ACCESS_KEY_STUDY = None
AWS_DEFAULT_REGION_STUDY = None


# Optionally, protect VM spawning
RECAPTCHA_SITE_KEY=None
RECAPTCHA_SECRET_KEY=None


# Optionally, to make docker pull easier
DOCKERHUB_REPO = None
# + username, password


# If setting up email sending
DEFAULT_FROM_EMAIL = "archive@archive.ooo"
SERVER_EMAIL = DEFAULT_FROM_EMAIL


# Slight paranoia
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SAMESITE = 'Strict'
CSRF_COOKIE_SECURE = True


# Directories files are written to
#
# At a minimum, the runner must have write access IMAGES_DOWNLOAD_ROOT, as this is where docker images are saved.
# If not using S3, it must also be exposed publicly for downloads (IMAGES_DOWNLOAD_URL).
# The same considerations apply to PUBLIC_FILES_ROOT and PUBLIC_FILES_URL
#
# They are similar in concept to Django's media/upload dir
PUBLIC_FILES_ROOT = BASE_DIR + '/public_files/'
PUBLIC_FILES_URL = 'https://'+MY_DOMAIN_NAME+'/public_files/'
IMAGES_DOWNLOAD_ROOT = BASE_DIR + '/dockerimg/'   # docker save
IMAGES_DOWNLOAD_URL = 'https://'+MY_DOMAIN_NAME+'/dockerimg/'
if os.getenv("DJANGO_S3_BUCKET"):
    S3_BUCKET = os.getenv("DJANGO_S3_BUCKET")


# See Django's docs
ALLOWED_HOSTS = [ MY_DOMAIN_NAME, ]



#####################################################################
# Settings can be kept outside git...
#####################################################################
logger = logging.getLogger("OOO")
try:
    from .local_settings_outside_git import *
except ImportError:
    logger.warning("I couldn't import local_settings_outside_git, will take settings from environment variables like $DJANGO_SECRET_KEY")


#####################################################################
# ... and some can also come from the environment
#####################################################################
if os.getenv('DJANGO_SECRET_KEY') is not None:
    SECRET_KEY = os.getenv('DJANGO_SECRET_KEY')
if os.getenv('DJANGO_DEBUG') is not None:
    DEBUG = bool(os.getenv('DJANGO_DEBUG'))
if os.getenv('DJANGO_ADMINS') is not None:
    ADMINS = os.getenv('DJANGO_ADMINS').split()


# ... including a DATABASE_URL
if not "DATABASES" in vars():
    import dj_database_url
    DATABASES = {}
    DATABASES['default'] = dj_database_url.config(conn_max_age=600,
            default="sqlite:///" + BASE_DIR + '/db.sqlite3')






#####################################################################
#
# The rest is typically fine as-is
#


LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/"


# Application definition

INSTALLED_APPS = [
    'ctfoood.apps.CtfooodConfig',
    'django.contrib.humanize',

    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'archiveooo.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'archiveooo.wsgi.application'


# Password validation
# https://docs.djangoproject.com/en/3.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
#    {
#        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
#    },
#    {
#        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
#    },
#    {
#        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
#    },
#    {
#        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
#    },
]


# Internationalization
# https://docs.djangoproject.com/en/3.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

# Leaving it as UTC by default (note: should also set $TZ for subprocesses)
TIME_ZONE = 'UTC'

# gettext() translation -- disabled for now
USE_I18N = False

# Input/output of dates, numbers, etc. -- disabled for now
USE_L10N = False

# Store UTC, convert as needed
USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.0/howto/static-files/

STATIC_URL = '/static/'
