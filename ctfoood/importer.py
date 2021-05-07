# Auto-import the challenge from a git repository
# Called either from the web (from the private challenge view) or from the command line

from django.conf import settings
from django.contrib.auth.models import User
import django.utils.timezone
import hashlib
import hmac
import logging
import os
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import yaml
from typing import BinaryIO, List, Optional, Tuple

from .helpers import make_deploy_key_file, service_port_validator, _clean_name_for_tags
from .models import Chal, ChalCheckout, Tag, PublicFile, VM, TYPE_CHOICES
from .containering import push_to_dockerhub

logger = logging.getLogger("OOO")


FLAG_RE = r"OOO{[^}]*}\Z"


def load_info_yaml(destdir):
    if os.path.isfile(os.path.join(destdir, 'info.yml')):
        info_yml_filename = 'info.yml'
    elif os.path.isfile(os.path.join(destdir, 'info.yaml')):
        info_yml_filename = 'info.yaml'
    else:
        assert False, "info.y[a]ml not found!"
    with open(os.path.join(destdir, info_yml_filename)) as yf:
        return yaml.safe_load(yf)


def _runcmd(cmdarr: List[str], cwd:Optional[str]=None, timeout:Optional[int]=500, env=None,
        real_terminal:bool=False) -> Tuple[int, str]:
    """Returns returncode, output"""
    logger.debug("_runcmd %s", ' '.join(shlex.quote(x) for x in cmdarr))
    output : str = ""
    cmds = ' '.join(shlex.quote(x) for x in cmdarr)
    cmds = 'nice ionice -c3 ' + cmds
    if real_terminal:
        with tempfile.TemporaryDirectory(prefix="mio_runcmd_out") as td:
            tmpname = os.path.join(td, "output")
            p = subprocess.run(['script', '-c', cmds, '-q', '--return', tmpname],
                universal_newlines=True,  # just to keep mypy happy
                cwd=cwd, timeout=timeout, env=env)
            with open(tmpname) as tf:
                output = tf.read()
    else:
        p = subprocess.run(cmds, shell=True,
            universal_newlines=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, input="",
            cwd=cwd, timeout=timeout, env=env)
        output = p.stdout
    if p.returncode != 0:
        logger.debug("_runcmd finished with returncode %d, stdout len %d", p.returncode, len(output))
    return p.returncode, output


def _get_s3():
    if settings.S3_BUCKET:
        import boto3
        p = settings.AWS_PROFILE
        avail = boto3.Session().available_profiles
        session = boto3.Session(profile_name=p if (p in avail) else None,
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY)
        return session.resource("s3")
    return None

def _upload_to_s3(basedir: str, fp: BinaryIO, basename: str, its_sha256: str) -> str:
    """Returns the url"""
    # Similar to chalmanager. URLs always salted, always public.
    s3 = _get_s3()
    assert s3

    assert basedir in ('public_files', 'docker_images')

    salted_sha256 = hmac.new(key=settings.SECRET_KEY.encode('utf-8'),
            msg=its_sha256.encode("ascii"), digestmod='sha256').hexdigest()
    s3key = f"{basedir}/{salted_sha256}/{basename}"
    logger.info("Uploading to S3: {}".format(s3key))
    fp.seek(0)

    s3.meta.client.upload_fileobj(fp, settings.S3_BUCKET, s3key)
    # Make it so the s3 object we just uploaded is publically accessible
    obj = s3.Object(settings.S3_BUCKET, s3key)
    obj.Acl().put(ACL="public-read")
    assert obj.bucket_name == settings.S3_BUCKET
    assert s3.meta.client.get_bucket_location(Bucket=obj.bucket_name)['LocationConstraint'] == settings.AWS_REGION
    #logger.debug("Changed ACL on S3 key {} to 'public-read'".format(s3key))

    return f"https://s3.{settings.AWS_REGION}.amazonaws.com/{settings.S3_BUCKET}/{s3key}"


def run_tester_cmd(path:str, arg:str=None, format=None,
        ok_to_replace_with_standard_tester:bool=False,
        real_terminal=False, timeout:Optional[int]=500,
        log_level:str="WARNING",
        test_deployed:Optional[VM]=None, just_healthcheck:bool=False) -> Tuple[int, str, bool, bool]:
    """Returns: exitcode, output, had_errors, had_warnings"""
    if just_healthcheck: assert test_deployed is not None
    if not os.path.isfile(os.path.join(path, 'tester')):
        return 0, "INTERNAL WARNING : There is no ./tester (!)", False, True

    cmd : List[str] = ['python3', '-u']
    if ok_to_replace_with_standard_tester:
        cmd += [os.path.join(settings.BASE_DIR,
                'tester_finals' if format.endswith('f') else 'tester_quals'),
            '--use-cwd', '--log-level', log_level]
    else:
        with open(os.path.join(path, 'tester')) as tf:
            tester_code = tf.read()
        if re.search('\Wno-self-update\W', tester_code):
            cmd.append('--no-self-update')
        if re.search('--incognito\W', tester_code):
            cmd.append('--incognito')
        if re.search('\Wlog-level\W', tester_code):
            cmd.append('--log-level='+log_level)
        if real_terminal and re.search('\Wforce-color\W', tester_code):
            cmd.append('--force-color')

    if test_deployed is not None:
        assert test_deployed and not arg
        vm:VM = test_deployed
        if just_healthcheck:
            cmd += ['healthcheck']
        elif format.endswith('q'):
            cmd += ['test_deployed', 'exploit']
        else:
            cmd += ['test']
        cmd += [str(vm.ip), str(vm.checkout.exposed_port)]  # host_net?

    if arg:
        cmd.append(arg)

    tester_output : str = "[*] Running: " + ' '.join(shlex.quote(x) for x in cmd) + "\n"
    logger.info("Running the tester: " + ' '.join(shlex.quote(x) for x in cmd))
    returncode, cmdoutput = _runcmd(cmd, timeout=timeout, cwd=path, real_terminal=real_terminal)
    tester_output += cmdoutput
    if returncode != 0:
        return returncode, tester_output, True, True

    # TODO: copied from_chalmanager.py
    tester_output = '\n'.join(l for l in tester_output.splitlines() \
            if ('WARNING Public file:' not in l) \
            and ('LogLevel' not in l) \
            and ('log-level' not in l) \
            and ('to the list of known hosts' not in l) \
            and ('PLEASE VERIFY THAT THE PUBLIC FILES ARE CORRECT' not in l) \
            and ('PLEASE VERIFY THAT THIS IS CORRECT: files in public bundle:' not in l))

    tester_gave_errors = any(x in tester_output for x in \
            ('CRITICAL', 'ERROR', 'EXCEPTION', 'AssertError'))
    tester_gave_warnings = ('WARNING ' in tester_output)
    return 0, tester_output, tester_gave_errors, tester_gave_warnings


def git_clone(chal: Chal, pull_from:str, pull_branch:str, submodules:bool=True,
        real_terminal=False) -> Tuple[int, str, str, str, Optional[str]]:
    """Return returncode, output, commit_hash, temp dir containing clone, deploy key temp file"""
    clone_output = ""
    destdir = tempfile.mkdtemp(prefix='mio_clone_', suffix="__"+chal.name)

    # Note: pull_branch, pull_from, submodules actually have defaults in Chal
    #       do_autopull handles that for now

    assert pull_from
    cmd = ['git','clone','-q','--depth=1','--no-tags']
    if submodules:
        cmd += ['--shallow-submodules','--recurse-submodules']
    # TODO[opt]: --reference-if-able=previous_checkout --dissociate
    if pull_branch:
        cmd += ['-b', pull_branch ]
    cmd += [ pull_from, destdir ]

    cmdenv = os.environ.copy()
    cmdenv['GIT_ASKPASS'] = '/bin/true' # So it won't ask for passwords
    cmdenv["GIT_SSH_COMMAND"] = "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=ERROR"
    dkf = None
    if chal.autopull_deploy_key:
        # Should also accept default local keys
        dkf = make_deploy_key_file(chal.autopull_deploy_key)
        cmdenv["GIT_SSH_COMMAND"] += " -i " + shlex.quote(dkf)
        clone_output += "[ ] Deploy key exported, cmdenv set\n"
        logger.info("do_autopull deploy key: %s", dkf)

    logger.info("git cloning %s%s", chal.name, f" (branch: {pull_branch})" if pull_branch else "")
    clone_output += "[*] Running: " + ' '.join(shlex.quote(x) for x in cmd) + "\n"
    returncode, cmdoutput = _runcmd(cmd, env=cmdenv, real_terminal=real_terminal)
    clone_output += cmdoutput
    if returncode != 0:
        return returncode, clone_output, "", "", dkf

    commit_hash = subprocess.check_output(["git","rev-parse","HEAD"],
            cwd=destdir, universal_newlines=True).strip()
    clone_output += "\ngit rev-parse HEAD: " + commit_hash + "\n"
    return returncode, clone_output, commit_hash, destdir, dkf


def grep_for_exposed_port(service_dir) -> Optional[int]:
    try:
        service_Dockerfile = os.path.join(service_dir, 'service', 'Dockerfile')
        expose_grep: str = subprocess.check_output(['egrep','-i','^[[:space:]]*expose',service_Dockerfile], 
                universal_newlines=True).strip()
        assert len(expose_grep.splitlines()) == 1, "More than one EXPOSE line in the service Dockerfile? Found: {}".format(expose_grep)
        m = re.match(r'\s*EXPOSE\s*([0-9]+)(/(tcp|udp))?', expose_grep, re.I)
        assert m, "I didn't understand the expose statement in the service Dockerfile ('{}')".format(expose_grep)
        return int(m.group(1))
    except Exception as e:
        logger.warning("Exception while grepping for EXPOSE: %s %s", type(e), str(e))
        return None


def do_autopull(chal: Chal, user: User, run_tester:bool=False,
        pull_from:str=None, pull_branch:str=None, is_autopull:bool=True,
        real_terminal=False, docker_cleanup=True, make_public:bool=False,
        as_default:bool=False, dockerhub:bool=False,
        tester_log_level:str="WARNING",
        submodules: Optional[bool]=None,
        just_test_deployed:Optional[VM]=None, just_healthcheck:bool=False) -> Tuple[int, str, Optional[ChalCheckout]]:
    """Returns errcode, output, resulting_checkout_object"""

    assert not as_default or make_public
    assert not dockerhub or make_public

    #### 0. Lock checking out this challenge (docker tag names, etc.)
    chal_lockfile = f"/tmp/archiveooo_lock_{chal.name}"
    lockfile = None
    try:
        lockfile = open(chal_lockfile, "x")
    except FileExistsError:
        rd = "[ Couldn't read f{chal_lockfile} ! ]"
        with open(chal_lockfile, "r") as rdf:
            rd = rdf.read()
        logger.warning(f"There's another autopull in progress for challenge {chal.name} -- data: {rd}")
        return 5212, f"There's another autopull in progress for challenge {chal.name} -- data: {rd}", None
    lockfile.write(f"Creation time: {django.utils.timezone.now()}\n")
    lockfile.write(f"PID: {os.getpid()}\n")
    lockfile.close()

    dkf = None; destdir = None
    try:
        logger.debug("do_autopull chal %s", chal)
        creation_start_time = django.utils.timezone.now()
        assert chal.has_private_access(user)

        #### 1. git clone
        if pull_from is None:
            pull_from = chal.autopull_url
        if pull_branch is None:
            pull_branch = chal.autopull_branch
        if submodules is None:
            submodules = chal.autopull_submodules
        if submodules is None:
            # If it was never specified, default to yes
            submodules = True
        returncode, clone_output, commit_hash, destdir, dkf = git_clone(chal=chal,
                pull_from=pull_from, pull_branch=pull_branch, submodules=submodules,
                real_terminal=real_terminal)
        if returncode != 0:
            logger.error("git clone failed (%s) %s %s -- %s", chal, pull_from, pull_branch, clone_output)
            return returncode, clone_output, None
        all_output = clone_output


        #### 2. Run the tester if asked to, including with just_test_deployed
        tester_output = ""; tester_gave_errors = False; tester_gave_warnings = False
        if run_tester or just_test_deployed is not None:
            tester_returncode, new_output, new_errors, new_warnings = run_tester_cmd(destdir, format=chal.format,
                    timeout=None if real_terminal else 500,
                    real_terminal=real_terminal,
                    log_level=tester_log_level,
                    ok_to_replace_with_standard_tester=True,
                    test_deployed=just_test_deployed, just_healthcheck=just_healthcheck)
            tester_gave_errors |= new_errors
            tester_gave_warnings |= new_warnings
            all_output += "\n\n" + new_output + "\n\n"
            tester_output += "\n\n" + new_output + "\n\n"
            if tester_returncode != 0:
                logger.warning("./tester failed (exit code %d) for %s", tester_returncode, chal)

        #### Special: just_test_deployed ends here
        if just_test_deployed is not None:
            existing_checkout = just_test_deployed.checkout
            existing_checkout.ran_test_deployed = True
            existing_checkout.tester_output += "\n\n\n--- test_deployed ---\n\n"
            existing_checkout.tester_output += all_output
            existing_checkout.save()
            all_output += "\n[ ] just_test_deployed finished, see the output above (also added to the db)   {}\n".format(just_test_deployed)
            if tester_gave_errors:
                existing_checkout.tester_gave_errors = True
                all_output += "[E] I think there were errors (see output)\n"
            if tester_gave_warnings:
                existing_checkout.tester_gave_warnings = True
                all_output += "[W] I think there were warnings (see output)\n"
            return 0, all_output, None


        #### 3. Extract info and create the base ChalCheckout
        logger.debug("Parsing info.yml...")
        y = load_info_yaml(destdir)

        if 'service_name' in y:
            assert _clean_name_for_tags(y['service_name']).replace('-','') == chal.get_clean_name_for_tags().replace('-',''), \
                    f"The info.yml service_name ({y['service_name']}) doesn't look like the current chal.name ({chal.name})"

        if not y.get('game_network_info'):
            logger.warning("No game_network_info, is this service intended to be offline? Mark it as such in the admin interface.")
        elif y['game_network_info'].get('host') != 'default':
            logger.error("This challenge specifies a custom host endpoint: %s", y['game_network_info']['host'])
            logger.info("Full game_network_info: %s", y['game_network_info'])

        exposed_port = None
        if os.path.exists(os.path.join(destdir, "service", "Dockerfile")):
            if 'container_port' in y:  # Note that container_port can be != game_port (which we don't need to use, the endpoint is directly the container)
                exposed_port = y['container_port']
            elif y.get('game_network_info',{}).get('port','guess') != 'guess':
                exposed_port = y['game_network_info']['port']
            else:
                exposed_port = grep_for_exposed_port(destdir)
            try:
                exposed_port = int(exposed_port)
                service_port_validator(exposed_port)
            except Exception as e:
                all_output += "Invalid exposed port (%s) %s %s" % (exposed_port, type(e), str(e))
                logger.warning("Invalid exposed port (%s) %s %s", exposed_port, type(e), str(e))
                exposed_port = None

        if 'flag' in y:
            flag = y['flag']
        elif 'initial_flag' in y:
            flag = y['initial_flag']
        elif 'default_flag' in y:
            flag = y['default_flag']
        elif os.path.isfile(os.path.join(destdir, 'flag')):
            with open(os.path.join(destdir, 'flag')) as ff:
                flag = ff.read()
        else:
            logger.warning("No flag file or entry in info.yml! (%s)", chal.name)
            all_output += "WARNING: No flag file or entry in info.yml!\n"
            flag = None

        violates_flag_format = y.get('violates_flag_format', False)
        if not re.match(FLAG_RE, flag):
            violates_flag_format = True

        chaltype = y.get('type', 'normal')
        if chaltype == "jeopardy":
            assert chal.format.endswith('q')
            chaltype = 'normal'
        if chal.type != chaltype:
            logging.warning("Adjusting challenge type: %s -> %s", chal.type, chaltype)
            all_output += "Adjusting challenge type: %s -> %s" % (chal.type, chaltype)
            assert chaltype in [ tc[0] for tc in TYPE_CHOICES ]
            chal.type = chaltype
            chal.full_clean()
            chal.save()


        logger.debug("Creating ChalCheckout...")
        checkout = ChalCheckout(chal=chal, cache=destdir,
                creation_info=all_output, creation_user=user,
                creation_time=creation_start_time,

                ran_tester=bool(run_tester),
                tester_output=tester_output,
                tester_gave_errors=tester_gave_errors, tester_gave_warnings=tester_gave_warnings,

                commit_hash=commit_hash, dirty_tree=False, via_autopull=is_autopull,
                pull_url=pull_from, branch=pull_branch,

                description=y['description'], authors=', '.join(y.get('authors',[])),
                default_flag=flag, exposed_port=exposed_port,
                violates_flag_format=violates_flag_format)
        checkout.full_clean()
        checkout.save()
        all_output += f"Checkout object created: {checkout}\n"
        logger.debug("ChalCheckout object created: %s", str(checkout))


        #### 4. docker build (not ./tester build)
        if os.path.exists(os.path.join(destdir, "service", "Dockerfile")):
            # Mimics tester build_service(), but with a custom tag
            cmd = ['docker','build']
            if y.get('copy_flag_using_build_arg'):
                # TODO: It would be cool to rebuild at every invocation with random flags
                #       Right now very few chals have copy_flag_using_build_arg=True
                cmd += ["--build-arg", "THE_FLAG='%s'" % flag ]
                logger.debug("copy_flag_using_build_arg is true, passing arg THE_FLAG='%s'", flag)
            cmd += ['-t', checkout.get_imgtag(), "."]
            all_output += "\n\n[*] Will run " + ' '.join(shlex.quote(x) for x in cmd) + '\n'
            logger.info("docker build -t %s", checkout.get_imgtag())
            returncode, cmdoutput = _runcmd(cmd, cwd=os.path.join(destdir,"service"),
                    timeout=None if real_terminal else 600)
            if returncode != 0:
                logger.warning("docker build failed (exit code %d) for %s: %s", returncode, chal, cmdoutput)
                all_output += "\n\n" + cmdoutput
                return returncode, all_output, checkout
            all_output += "Docker build successful\n"
            checkout.docker_image_built = True
            all_output += "\n[*] Creating the tar.gz (docker save + gzip)"
            tgzpath, tgzurl, tgzsha256 = create_docker_image_tar(checkout.get_imgtag())
            if not tgzurl:
                all_output += "\nWTF I could docker build but not docker save?!?\n"
                logger.critical("WTF I could docker build but not docker save?!?")
                return 4444, all_output, checkout
            checkout.docker_image_tgzpath = tgzpath
            checkout.docker_image_tgzurl = tgzurl
            checkout.docker_image_tgzsha256 = tgzsha256
            checkout.save()


        #### 5. docker push (to Amazon ECR)
        if dockerhub:
            assert make_public
            assert settings.DOCKERHUB_REPO
            logger.info("Pushing to dockerhub (%s)", settings.DOCKERHUB_REPO)
            all_output += "\n[*] Pushing to Docker Hub...\n"
            checkout.dockerhub_uri = push_to_dockerhub(checkout, as_default=as_default, real_terminal=real_terminal)
            all_output += f"[+] Pushed, available on dockerhub as {checkout.dockerhub_uri}\n\n"
            checkout.save()
        else:
            logger.info("No docker push")
            all_output += "\nSkipping docker registry push\n\n"


        #### 6. Tags
        if 'speedrun' in chal.name:
            y['tags'].append('speedrun')
        if chal.format.endswith('f'):
            y['tags'].append('finals')
            if not chal.points:
                chal.points = 1000
                chal.save()
        for t in y['tags']:
            tname = t.lower()
            if tname == 're': tname = 'reversing'
            if tname == 'reverse': tname = 'reversing'
            if tname == 'shellcode': tname = 'shellcoding'
            if tname == 'warmup': tname = 'intro'
            tobj, is_new_tag = Tag.objects.get_or_create(name=tname)
            if is_new_tag:
                logger.info("New tag created: %s", t)
                all_output += f"New tag created: {t}\n"
            checkout.tags.add(tobj)
        checkout.save()

        #### 7. Public files
        if y.get('public_files', None):
            # First try to get them directly from the repository
            public_files_done = True
            for pf_local_path in y['public_files']:
                try:
                    bname = os.path.basename(pf_local_path)
                    with open(os.path.join(destdir, pf_local_path), 'rb') as openf:
                        pf = create_public_file(bname, openf, checkout=checkout)
                    all_output += f"   {pf.filename} {pf.sha256}   <--  {pf_local_path}\n"
                except Exception as e:
                    logging.debug("Could not copy public file '%s' directly: %s %s", pf_local_path, type(e), e)
                    public_files_done = False
            # If something is still missing, try the public_bundle, building it (./tester bundle) if necessary
            if not public_files_done:
                tarname = os.path.join(destdir, 'public_bundle.tar.gz')
                if not os.path.exists(tarname):
                    all_output += "\n\n[*] We have to ./tester build to get all public files...\n"
                    logging.debug("We have to ./tester build")
                    tester_returncode, tester_output, tester_gave_errors, tester_gave_warnings = run_tester_cmd(destdir, arg='build', format=chal.format, real_terminal=real_terminal, timeout=None if real_terminal else 500)
                    all_output += "\n\n" + tester_output + "\n\n"
                    if tester_returncode != 0:
                        logger.warning("tester build failed (exit code %d) for %s: %s", tester_returncode, chal, tester_output)
                        return tester_returncode, all_output, None
                logger.info("Parsing public_bundle.tar.gz")
                all_output += "\n\n[*] Parsing public_bundle.tar.gz\n"
                with tarfile.open(tarname) as tarf:
                    dirnames = [ m.name for m in tarf.getmembers() if m.isdir() ] 
                    skip_one_dir = False
                    if len(dirnames) == 1:
                        # TODO: transparently handle directories (tgz only if necessary)
                        skip_one_dir = True
                        all_output += f"Found one dir ('{dirnames[0]}'): will skip that in filenames\n"
                        logger.debug(f"Found one dir ('{dirnames[0]}'): will skip that in filenames")
                    for tarmember in tarf.getmembers():
                        if tarmember.isdir():
                            continue
                        bname = tarmember.name.replace('/', '__')  # XXX: hackish
                        if skip_one_dir and bname.startswith(dirnames[0] + "__"):
                            bname = bname[len(dirnames[0]+'__'):]
                        if not re.match("[A-Za-z0-9_ .-]+\Z", bname) \
                                or not tarmember.isfile():
                            logger.error("Weird tarfile member %s %s", tarmember.name, repr(tarmember))
                            all_output += f"INTERNAL CRITICAL ERROR: Rejecting {tarmember.name}\n"
                            continue
                        pf = create_public_file(bname, tarf.extractfile(tarmember), checkout=checkout) # type: ignore[arg-type]
                        all_output += f"   {pf.filename} {pf.sha256}\n"
                        public_files_done = True

        #### 8. make_public, cleanup, etc.
        if make_public:
            checkout.public = True
            checkout.save()
        if as_default:
            assert make_public
            checkout.chal.public_checkout = checkout
            checkout.chal.save()

        checkout.full_clean()
        checkout.save()
        return 0, all_output, checkout
    except Exception as e:
        logger.exception("Exception while creating checkout for %s - %s  (in %s)", chal.format, chal.name, destdir)
        return 4669, f"!! Internal exception !! {type(e)} {e}", None
    finally:
        #### 9. Cleanup
        if docker_cleanup:
            logger.debug("Cleaning up docker processes and images...")
            _, ps = _runcmd(['docker','ps','--all','--format','{{.ID}} {{.Repository}} {{.Tag}}'])
            for l in ps.splitlines():
                if (chal.name in l) or (chal.get_clean_name_for_tags() in l):  # XXX: very rough way of matching
                    logger.warning("There was still a docker process, force-removing it: %s", l.strip())
                    subprocess.call(['docker', 'rm', '-f', l.split()[0]])
            _, images = _runcmd(['docker','images','--format','{{.ID}} {{.Repository}} {{.Tag}}'])
            for l in images.splitlines():
                if (chal.name in l) or (chal.get_clean_name_for_tags() in l):  # XXX: very rough way of matching
                    # This one is normal: logger.debug("Removing matched docker image: %s", l.strip())
                    _runcmd(['docker', 'rmi', '-f', l.split()[0]])
        if destdir: shutil.rmtree(destdir)
        if lockfile: os.unlink(chal_lockfile)
        if dkf: os.unlink(dkf)
        pass  # pytype: disable=bad-return-type




def create_public_file(name: str, fp: BinaryIO, checkout: Optional[ChalCheckout]=None) -> PublicFile:
    """Stores both locally (or in S3_BUCKET) and in the db + associates the file with the ChalCheckout"""
    assert re.match("[A-Za-z0-9_ .-]+\Z", name)
    content = fp.read()
    its_sha256 = hashlib.sha256(content).hexdigest()

    if _get_s3():
        fp.seek(0)
        url = _upload_to_s3('public_files', fp, name, its_sha256)  # basedir name used in delete_stale_files too
        local_path = None
    else:
        salted_sha256 = hmac.new(key=settings.SECRET_KEY.encode('utf-8'),
                msg=its_sha256.encode("ascii"), digestmod='sha256').hexdigest()

        relative_dir = salted_sha256[0] + '/' + salted_sha256
        relative_path = relative_dir + '/' + name
        local_dir= os.path.join(settings.PUBLIC_FILES_ROOT, relative_dir)
        local_path = os.path.join(settings.PUBLIC_FILES_ROOT, relative_path)

        os.makedirs(local_dir, mode=0o755, exist_ok=True)
        if os.path.exists(local_path):
            with open(local_path, 'rb') as f:
                oldcontent = f.read()
            oldsha256 = hashlib.sha256(oldcontent).hexdigest()
            if its_sha256 != oldsha256:
                logger.critical("CORRUPT LOCAL PUBLIC FILE?!? %s", local_path)
                assert its_sha256 == oldsha256, f"corrupt local file, not sure what to do: {local_path}"
        else:
            with open(local_path, 'wb') as f:
                f.write(content)
                os.fchmod(f.fileno(), mode=0o644)

        url = settings.PUBLIC_FILES_URL + relative_path

    pf = PublicFile(checkout=checkout, filename=name, sha256=its_sha256,
            local_path=local_path, url=url)
    pf.full_clean()
    pf.save()
    return pf


def create_docker_image_tar(tag: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Returns local_path, URL, SHA256"""
    assert re.match("[A-Za-z0-9:-]+\Z", tag)
    salted_tag = hmac.new(key=settings.SECRET_KEY.encode('utf-8'),
            msg=tag.encode("ascii"), digestmod='sha256').hexdigest()

    if settings.S3_BUCKET:
        rootdir = tempfile.mkdtemp(prefix="mia_dockerimg_")
    else:
        rootdir = settings.IMAGES_DOWNLOAD_ROOT

    tarbasename = tag.replace(':','__') + '.tar'
    relative_dir = salted_tag[0] + '/' + salted_tag
    relative_path_tar = relative_dir + '/' + tarbasename
    relative_path_tar_gz = relative_path_tar + ".gz"
    local_dir = os.path.join(rootdir, relative_dir)
    local_path_tar = os.path.join(rootdir, relative_path_tar)
    local_path_tar_gz = os.path.join(rootdir, relative_path_tar_gz)

    os.makedirs(local_dir, mode=0o755, exist_ok=True)
    assert not os.path.exists(local_path_tar)
    assert not os.path.exists(local_path_tar_gz)

    try:
        logger.debug("Running docker save...")
        subprocess.check_call(['docker','save', '-o', local_path_tar, tag], stdin=subprocess.DEVNULL)
        assert os.path.exists(local_path_tar)
        gzipper = "pigz" if subprocess.call(["which","pigz"], stdout=subprocess.DEVNULL) == 0 else "gzip"
        logger.debug("Compressing the docker-saved tar with %s...", gzipper)
        subprocess.check_call([gzipper, local_path_tar], stdin=subprocess.DEVNULL)
        assert os.path.exists(local_path_tar_gz)
        assert not os.path.exists(local_path_tar)
        logger.debug("Taking its sha256sum...")
        sha256sum = subprocess.check_output(['sha256sum', local_path_tar_gz],
                universal_newlines=True, stderr=subprocess.STDOUT)
        assert len(sha256sum.splitlines()) == 1
        sha256 = sha256sum.split()[0]
    except Exception:
        logger.exception("Docker save or gzip exception!")
        return None, None, None

    if not _get_s3():
        os.chmod(local_path_tar_gz, 0o444)
        return local_path_tar_gz, (settings.IMAGES_DOWNLOAD_URL + relative_path_tar_gz), sha256
    with open(local_path_tar_gz, 'rb') as lf:
        url = _upload_to_s3('docker_images', lf, tarbasename + '.gz', sha256)  # basedir name used in delete_stale_files too
    shutil.rmtree(rootdir)
    return None, url, sha256


def test_deployed(vm: VM, user:User, just_healthcheck:bool=False,
        real_terminal:bool=False, log_level:str="WARNING") -> Tuple[int, str]:
    errcode, output, _ = do_autopull(chal=vm.checkout.chal, user=user,
            just_test_deployed=vm, just_healthcheck=just_healthcheck, tester_log_level=log_level,
            real_terminal=real_terminal)
    return errcode, output
