from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from django.core.mail import send_mail
from django.core.exceptions import PermissionDenied
from django.core.validators import EmailValidator
from django.views.decorators.http import require_POST, require_safe
from django.views.decorators.vary import vary_on_cookie
from django.views.decorators.cache import cache_control, never_cache, patch_cache_control
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.contrib import messages
from django.db import transaction
import django.urls
import collections
import ipaddress
import json
import logging
import re
import urllib.parse
from urllib.request import urlopen
from markdown import markdown


from .models import Chal, ChalCheckout, UserSettings, Achievement, Tag, VM
from .importer import do_autopull, test_deployed
from .helpers import get_user_ip
from .spawner import spawn_ooo, delete_ooo_vm, minimize_egress, disable_metadata_access, update_vm_ip
from .containering import push_to_dockerhub


logger = logging.getLogger("OOO")


def get_settings(user: User) -> UserSettings:
    """Gets or creates an empty one"""
    assert user.is_authenticated
    s, _ = UserSettings.objects.get_or_create(user=user, defaults={'user': user})
    return s


def add_solve(user: User, chal: Chal, request=None) -> None:
    if not user.is_authenticated:
        return
    us = get_settings(user)
    us.solved.add(chal)
    recalculate_achievements(user, request)


def set_achievement(us: UserSettings, a: Achievement, give:bool=True, request=None) -> None:
    if give:
        if request and a not in us.achievements.all():
            messages.success(request, f"Got achievement '{a}'")
        us.achievements.add(a)
    else:
        us.achievements.remove(a)


def recalculate_achievements(user: User, request=None) -> None:
    us = get_settings(user)
    public_chals = Chal.objects.filter(public_checkout__isnull=False)\
            .exclude(solved_by=us).order_by('-format', 'name')  # TODO: easy first?
    solved_chals = Chal.objects.filter(public_checkout__isnull=False,
            solved_by=us).order_by('-format', 'name')
    # Tag-based achievements
    solved_tagged = collections.defaultdict(list)
    unsolved_tagged = collections.defaultdict(list)
    for c in solved_chals:
        for t in c.get_tags():
            solved_tagged[t].append(c)
    for c in public_chals:
        for t in c.get_tags():
            unsolved_tagged[t].append(c)
    for a in (x for x in Achievement.objects.all() if x.tag):
        set_achievement(us, a, bool(not unsolved_tagged[a.tag] and solved_tagged[a.tag]), request)
    # Point-based achievements
    for a in (x for x in Achievement.objects.all() if x.points):
        set_achievement(us, a, us.points() >= a.points, request)


def valid_recaptcha(request) -> bool:
    if not settings.RECAPTCHA_SITE_KEY:
        logger.info("Skipping recaptcha validation")
        return True
    if not request.POST.get('g-recaptcha-response'):
        return False
    try:
        post_dict = {'secret': settings.RECAPTCHA_SECRET_KEY,
                    'response': request.POST.get('g-recaptcha-response'),
                    'remoteip': get_user_ip(request)}
        post_data = urllib.parse.urlencode(post_dict).encode('utf-8')
        with urlopen("https://www.google.com/recaptcha/api/siteverify", post_data, timeout=10) as gru:
            assert gru.getcode() == 200
            grj = json.load(gru)
            logger.info("Got recaptcha response: %s", grj)
            return grj["success"]
    except Exception:
        if settings.DEBUG:
            raise
        return False

def add_recaptcha_sitekey(ctx):
    if settings.RECAPTCHA_SITE_KEY:
        ctx['recaptcha_sitekey'] = settings.RECAPTCHA_SITE_KEY
    return ctx


# TODO: search? django-filter? tables2?

@require_safe
@vary_on_cookie
def homepage(request):
    def tagorder(c: Chal):
        s = c.tags_str()
        return 0 if 'welcoming' in s else \
                1 if 'good_first_challenge' in s else \
                2 if 'intro' in s else 3
    own_private_chals = Chal.objects.filter(owner_user__id=request.user.id, public_checkout=None)
    grp_private_chals = Chal.objects.filter(owner_group__in=request.user.groups.all(), public_checkout=None)\
            .exclude(owner_user__id=request.user.id)
    if request.user.is_authenticated:
        # Also see the profile page
        us = get_settings(request.user)

        public_chals = list(Chal.objects.filter(public_checkout__isnull=False)\
                .exclude(solved_by=us).order_by('points', '-format', 'name'))
        # First push zero-points to the end
        public_chals.sort(key=lambda c: 1 if (c.points == 0) else 0)
        # Reorder: welcoming, good_first_challenge, intro
        public_chals.sort(key=tagorder)

        solved_chals = Chal.objects.filter(public_checkout__isnull=False,
                solved_by=us).order_by('-points', '-format', 'name')
        own_achievements = us.achievements.all()
        other_achievements = Achievement.objects.exclude(pk__in=own_achievements)
        own_vms = VM.objects.filter(creation_user=request.user, deleted=False).order_by('-id')
    else:
        public_chals = list(Chal.objects.filter(public_checkout__isnull=False)\
                .order_by('points', '-format', 'name'))
        # First push zero-points to the end
        public_chals.sort(key=lambda c: 1 if (c.points == 0) else 0)
        # Reorder: welcoming, good_first_challenge, intro
        public_chals.sort(key=tagorder)
        solved_chals = []
        own_achievements = []
        other_achievements = Achievement.objects.all()
        own_vms = []
    response = render(request, 'ctfoood/home.html', {
        "own_private_chals": own_private_chals,
        "grp_private_chals": grp_private_chals,
        "public_chals": public_chals,
        "solved_chals": solved_chals,
        "own_achievements": own_achievements,
        "other_achievements": other_achievements,
        "own_vms": own_vms,
    })
    if request.user.is_authenticated:
        patch_cache_control(response, max_age=0, must_revalidate=True)
    else:
        patch_cache_control(response, max_age=1800)
    return response


@require_safe
@never_cache  # for some reason, must_revalidate and vary_on_cookie were not enough on the private view (when accessed via cloudfront)
def chalpage(request, name):
    chal = get_object_or_404(Chal, name=name)
    if chal.has_private_access(request.user):
        return render(request, 'ctfoood/chal_private.html', {
            "chal": chal,
            "chal_meta": chal._meta,
            "public_checkouts": chal.checkouts.filter(public=True),
            "private_checkouts": chal.checkouts.filter(public=False),
        })
    if chal.public_checkout:
        return redirect(chal.public_checkout)
    get_object_or_404(Chal, name=name, public_checkout__isnull=False)  # Same 404 as above
    assert False


@vary_on_cookie
def checkoutpage(request, chalname, checkoutid):
    # TODO: split out this part or unify with spawn_vm
    checkout = get_object_or_404(ChalCheckout, id=checkoutid)
    chal = get_object_or_404(Chal, name=chalname)
    private = chal.has_private_access(request.user)
    this_is_the_public_checkout = (checkout == chal.public_checkout)
    if not private:
        chal = get_object_or_404(Chal, name=chalname, public_checkout=checkout)
        assert this_is_the_public_checkout

    got_valid_flag = False
    if request.method == "POST":
        if request.POST.get('checkout_id', None) == str(checkout.id) and \
            request.POST.get('flag', None) == checkout.default_flag:  # TODO: recaptcha or pow
            got_valid_flag = True
            if request.user.is_authenticated:
                add_solve(request.user, chal, request)

    # |linebreaks applied afterwards
    main_description = markdown(checkout.description, output_format='html5')
    extra_description = markdown(chal.extra_description, output_format='html5')

    special = None
    chal_type_description = 'a jeopardy'  # This was ___ challenge from {format}
    if Tag('speedrun') in checkout.get_tags():
        special = 'speedrun'
        chal_type_description = 'a speedrun'
    elif Tag('golf') in checkout.get_tags():
        special = 'golf'
        chal_type_description = 'a golf'
    elif chal.type == 'king_of_the_hill':
        special = 'finals'  # shared message
        chal_type_description = 'a King-of-the-Hill'
    elif chal.format.endswith('f'):
        special = 'finals'
        chal_type_description = 'an attack/defense'

    ctx = { "chal": chal, "checkout": checkout,
        "chal_meta": chal._meta, "checkout_meta": checkout._meta,
        "main_description": main_description, "extra_description": extra_description,
        "special": special, "chal_type_description": chal_type_description,
        "private": private, "this_is_the_public_checkout": this_is_the_public_checkout,
        "got_valid_flag": got_valid_flag, }
    if request.user.is_authenticated:
        ctx.update({
            "own_vms": VM.objects.filter(creation_user=request.user, deleted=False).order_by('-id'),
            "already_solved": chal.was_solved_by(request.user),
            "default_region": get_settings(request.user).fill_default_region(request),
            "user_ip": get_user_ip(request),
            "default_ip_whitelist": get_settings(request.user).fill_default_allowed_ip(request), })
    response = render(request, 'ctfoood/checkout.html', add_recaptcha_sitekey(ctx))
    if request.user.is_authenticated:
        patch_cache_control(response, max_age=0, must_revalidate=True)
    else:
        patch_cache_control(response, max_age=1800)
    return response



@require_POST
@never_cache
@login_required
def autopull(request, chalname):
    if not request.user.is_staff:
        raise PermissionDenied
    chal = get_object_or_404(Chal, name=chalname)
    if not chal.has_private_access(request.user):
        raise PermissionDenied
    errcode, output, checkout = do_autopull(
            chal=chal, user=request.user,
            run_tester=request.POST.get('run_tester'),
            make_public=request.POST.get('make_public'),
            dockerhub=request.POST.get('dockerhub'),
            as_default=request.POST.get('as_default'))
    return render(request, 'ctfoood/pgm_output.html',
            { "result": checkout, "result_meta": checkout._meta if checkout else None,
                "errcode": errcode, "output": output,
                "action": "website autopull", "chal": chal, "chal_meta": chal._meta, },
            status=500 if errcode else 200)


#TODO: @require_POST
@never_cache
@login_required
def post_push_to_dockerhub(request, checkoutid):
    if not request.user.is_staff:
        raise PermissionDenied
    checkout = get_object_or_404(ChalCheckout, id=checkoutid)
    chal = checkout.chal
    if not chal.has_private_access(request.user):
        raise PermissionDenied
    errcode, output = push_to_dockerhub(checkout, existing_checkout=True,
            as_default=(chal.public_checkout == checkout))
    return render(request, 'ctfoood/pgm_output.html',
            { "result": checkout, "result_meta": checkout._meta,
                "errcode": errcode, "output": output,
                "action": "push to dockerhub", "chal": chal, "chal_meta": chal._meta, },
            status=500 if errcode else 200)



@require_POST
@never_cache
@login_required
def spawn_vm_on_ooo(request, checkoutid):
    checkout = get_object_or_404(ChalCheckout, id=checkoutid)
    chal = checkout.chal
    private = chal.has_private_access(request.user)
    this_is_the_public_checkout = (checkout == chal.public_checkout)
    if not private:
        chal = get_object_or_404(Chal, name=chal.name, public_checkout=checkout)
        assert this_is_the_public_checkout

    if not valid_recaptcha(request):
        raise PermissionDenied

    if not request.POST.get('i_will_be_good'):
        raise PermissionDenied

    ip_str = request.POST.get('ooo_allowed_ip')
    if not ip_str:
        raise PermissionDenied
    try:
        ip = ipaddress.IPv4Address(str(ip_str))  # TODO: IPv6
        assert ip.is_global  # enough?
        assert not ip.is_multicast
        assert not ip.is_private
        assert not ip.is_unspecified
        assert not ip.is_reserved
        assert not ip.is_loopback
        assert not ip.is_link_local
        net = ipaddress.IPv4Network(str(ip) + '/32')
    except Exception:
        if settings.DEBUG:
            raise
        messages.error(request, "Invalid IP address.")
        return redirect(checkout)

    vmid, uuid = spawn_ooo(checkout=checkout, net=net, user=request.user)
    resp = f"{vmid},{uuid}" if vmid else "FAILED"
    return HttpResponse(resp, status=200 if vmid else 500)


# TODO: @require_POST
@never_cache
@login_required
def delete_vm(request, vmid):
    vm = get_object_or_404(VM, id=vmid, creation_user=request.user)
    errcode, output = delete_ooo_vm(vm)
    return render(request, 'ctfoood/pgm_output.html',
            { "errcode": errcode, "output": output, "action": "delete_vm", })




@never_cache
def register(request):
    if request.method == 'POST':
        if not valid_recaptcha(request):
            raise PermissionDenied
        form = UserCreationForm(request.POST)
        if form.is_valid():
            valid = True
            if request.POST['email']:  # XXX: is there a cleaner way to add this?
                try:
                    ev = EmailValidator()
                    ev(request.POST['email'])
                except Exception:
                    messages.error(request, "Invalid email address.")
                    valid = False
                if User.objects.filter(email=request.POST['email']).exists():
                    messages.error(request, "Someone else already registered with that email address!")
                    valid = False
            if not re.match(r'[a-z][a-z0-9_]+\Z', request.POST['username'], re.I):
                messages.error(request, "The username looks weird. Try limiting to letters, numbers, and underscores.")
                valid = False
            if valid:
                form.save()
                if request.POST['email']:
                    u = User.objects.get(username=request.POST['username'])
                    u.email = request.POST['email']
                    u.save()
                    if send_mail("Welcome to OOO's archive!",
                        f"""Greetings gentlehacker,\n\nIf you ever forget the password for your username ('{u.username}') we'll reset it from this email.\n\nMany challenges are very hard, but don't get discouraged: we run one of the hardest CTFs. We're gradually adding hints and links to write-ups, as well as making more challenges' server-side playable.\n\nWe hope you'll enjoy our archiving effort, and if you run into issues or have suggestions do contact us. Just keep in mind that preparing and running the competition is hard, and has priority over the archive.\n\nHack hard!\nOrder of the Overflow\n""",
                        from_email=settings.DEFAULT_FROM_EMAIL, recipient_list=(u.email,), fail_silently=True) != 1:
                            messages.error(request, "We couldn't send the welcome email -- probably, we won't be able to send password resets either.")
                return redirect('login')
    else:
        form = UserCreationForm()
    return render(request, 'ctfoood/register.html', add_recaptcha_sitekey({'form': form}))


@vary_on_cookie
def profile(request, username):
    if request.method == 'POST':
        raise NotImplementedError()
    # Also see the homepage
    u = get_object_or_404(User, username=username)
    us = get_settings(u)
    solved_chals = us.solved_chals()
    own_achievements = us.achievements.all()
    other_achievements = Achievement.objects.exclude(pk__in=own_achievements)
    is_own_profile = (request.user == u)
    return render(request, 'ctfoood/profile.html', {
        "solved_chals": solved_chals,
        "own_achievements": own_achievements,
        "other_achievements": other_achievements,
        "profiled": u, "profiled_settings": us,
        "is_own_profile": is_own_profile,
    })


@require_POST
@never_cache
@csrf_exempt
@transaction.atomic  # TODO: might actually want to guarantee correct ordering
def vm_pingback(request, vmid, uuid):
    vm = get_object_or_404(VM, id=vmid, pingback_uuid=uuid)
    logging.info("[vm %s]: %s", vm, request.POST.get('msg'))
    if not vm.ip:
        update_vm_ip(vm)
        vm.refresh_from_db()
    vm.pingback_received = True
    ts = django.utils.timezone.now().strftime("%H:%M:%S %Z")
    msg = request.POST.get('msg', '')
    vm.messagelog += f"[{ts}] {msg}\n"
    vm.latest_user_message = msg;
    if not vm.removed_metadata_access:
        if disable_metadata_access(vm):
            vm.messagelog += "(requested disabling AWS metadata access)\n"
            vm.removed_metadata_access = True
        else:
            vm.messagelog += "LOCAL ERROR IN DISABLING AWS METADATA ACCESS\n"
    if any(x in msg.lower() for x in ('final network settings', 'finished')):  # In case we miss the first one
        logging.info("%s reached the point at which we can minimize egress", vm)
        if minimize_egress(vm):
            vm.messagelog += "(locally edited the security group to remove egress)\n"
        else:
            vm.messagelog += "LOCAL ERROR IN EDITING THE SECURITY GROUP EGRESS RULES\n"
    vm.save()
    return HttpResponse(f'OK, pingback received at {ts}\n')


@require_POST
@never_cache
def get_vm_status(request):
    vm = get_object_or_404(VM,
            id=request.POST.get('vmid'),
            pingback_uuid=request.POST.get('vmuuid'))
    if not vm.ip:
        update_vm_ip(vm)
    r = f"{vm.ip},{vm.checkout.exposed_port},{vm.latest_user_message}"
    return HttpResponse(r)


@login_required
@never_cache
def run_test_deployed(request, vmid):
    vm = get_object_or_404(VM, id=vmid)
    checkout = vm.checkout
    chal = checkout.chal
    if not chal.has_private_access(request.user):
        vm = get_object_or_404(VM, id=vmid, creation_user=request.user)
        assert False
    errcode, output = test_deployed(vm, user=request.user)
    return render(request, 'ctfoood/pgm_output.html',
            { "result": checkout, "result_meta": checkout._meta if checkout else None,
                "errcode": errcode, "output": output,
                "action": "test_deployed", "chal": chal, "chal_meta": chal._meta, },
            status=500 if errcode else 200)



# Note: Normally this access is gated either by Apache authentication or via AWS CloudFront (which sets a specific header)
#       Direct access like /vm_pingback has to be specifically exempted (or the password added in MY_DOMAIN_NAME)
#       Also, there are some cases where for simplicity I'm assuming these are simply /foo without other paths
urlpatterns = [
    django.urls.path('', homepage, name='home'),
    django.urls.path('c/<name>/', chalpage, name='chalpage'),
    django.urls.path('c/<chalname>/<int:checkoutid>/', checkoutpage, name='checkoutpage'),

    django.urls.path('autopull/<chalname>/', autopull, name='autopull'),
    django.urls.path('push_to_dockerhub/<int:checkoutid>/', post_push_to_dockerhub, name='push_to_dockerhub'),
    
    django.urls.path('spawn_vm_on_ooo/<int:checkoutid>/', spawn_vm_on_ooo, name='spawn_vm_on_ooo'),
    django.urls.path('delete_vm/<vmid>/', delete_vm, name='delete_vm'),
    django.urls.path('run_test_deployed/<vmid>/', run_test_deployed, name='run_test_deployed'),
    django.urls.path('get_vm_status', get_vm_status, name='get_vm_status'),
    # TODO: cmd to replay pcap, run tester, ... django.urls.path('vm/<vmid>', vmpage),

    django.urls.path('accounts/', django.urls.include('django.contrib.auth.urls')),
    django.urls.path('register/', register, name='register'),
    django.urls.path('u/<username>', profile, name='profile'),

    django.urls.path('vm_pingback/<int:vmid>/<uuid>/', vm_pingback, name='vm_pingback'),

#    django.urls.path('search/<q>', searchpage),
#    django.urls.path('tag/<name>', tagpage),
]

from django.conf import settings
from django.conf.urls.static import static
if settings.DEBUG == True:
    urlpatterns += static(settings.PUBLIC_FILES_URL, document_root=settings.PUBLIC_FILES_ROOT)
    urlpatterns += static(settings.IMAGES_DOWNLOAD_URL, document_root=settings.IMAGES_DOWNLOAD_ROOT)
