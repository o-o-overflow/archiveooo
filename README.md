# CTFooD / archive.ooo

Built to archive CTF challenges -- in other words, to play at one's own leisure without time pressure. This is what powers [archive.ooo](https://archive.ooo)

Challenge data resides in a Django-managed database, but we gladly accept github issues for data too (for instance, hints and extra notes on existing challenges).

Brought to you with love from the <a href="https://oooverflow.io">Order of the Overflow</a>, current host of *the* <a href="https://defcon.org">DEF CON</a> CTF.


## Base idea

Base structure: Chal -> ChalCheckout(s) -> VM(s) / containers

  1. **Chal is the main challenge object** and holds its archival settings. This is the one that is edited manually, whereas the rest is chiefly auto-generated.

     It includes the name, year, format, additional fields to add to the page: extra_description, writeup URLs, link to hints and notes, ...

     It also includes the owner info (Django user/group) and info on how to autopull, if desired.

     It's useful to `./import.py --create-chal [...] (name) (git_repo)` to auto-generate the initial fields of this object instead of typing them manually.



  2. **ChalCheckout represents a "version" of the challenge**, typically a git commit (checkout). There can be multiple ChalCheckouts for each Chal.

     Create it via `./import.py` or via the private view of a Chal (available at /c/chalname if you're logged in). The git repository must be accessible (deploy keys are supported).

     Creating a ChalCheckout is the big archival operation, it includes pulling the challenge's public files, creating the docker images, and (if desired) uploading them to dockerhub, running the tester, etc.

     The object holds records of the creation-time info (what the tester returned, paths to the docker image, ...), the git info if available (commit hash, branch, ...) and
     most importantly the stuff that is persisted from `info.yml`: the challenge description, flag, tags, ...

     What is shown to the public is a Chal's ChalCheckout (hence the URLs like /c/Chal_name/ChalCheckout_id/).

     Virtually all of this object is auto-generated, the big exception is the `public` field.

     Checkouts are independent from each other, files included, and each has its own direct URL.



  3. When the user hits spawn (or we use `./spawn.py`) a **VM object** is created for that ChalCheckout.

     Besides recording creation info, VM objects also include the VM state as visible to the archive site: pingbacks are recorded in `messagelog`.

     Pingbacks are messages sent by the VM's init script (the user_data `runcmd` -- see `spawner.py`) to the archive, logging progress (downloading the image, starting it, etc.).

     The latest pingback is shown to the user (as `latest_user_message`, see `vm_pingback` in `views.py` and the periodic ajax fetch).
     Additionally, the "finished" pingback from the VM triggers editing the AWS security group to block egress.
     Note that the VM has iptables -- however this is incomplete and the main enforcement is via the AWS security group.

     VM normally shutdown themselves, and (since `InstanceInitiatedShutdownBehavior='terminate'`) they auto-cleanup their AWS instance.
     The `delete_aged_vms.py` script is run periodically to ensure termination and set the `deleted` field (the VM object is kept around as a record).

     There is currently only one init script, which loads and runs the docker image as in our standard format (both for quals and finals) in a small VM. Custom `vm_setups` are TODO.


Checkouts are private by default, to ease testing. S3 URLs are unpredictable, but do not require logins.
What is public is one main checkout for each challenge. The archive page shows that ChalCheckout (ideally, straight out of `./import.py`) + data from the base Chal (an extra description, additional tags, point value, links, hints, ...).

The Django admin interface serves as the main editor + a private per-challenge page that can be used to auto-pull a new checkout from git.


## Code
The code is not super-clean, but it's not that dirty either.

`ctfoood` is the django app inside the `archiveooo` project.

Splitting them should be fairly easy, but they really go together in practice. Similarly, URLs are expected to map to the site root's (e.g., `/c/chal` not `/foo/c/chal`) -- wouldn't be too hard to change if desired.

There are some special Tags and Achievements: for instance, speedrun-tagged challenges get a special message.


## Deployment

See the [_server_setup](./_server_setup) folder for more info.

Note that the config needs to know its domain name and IPv4 to construct pingback curl commands from the VM. Domains different than archive.ooo are supported (in fact, we run it on multiple domains, including one that is not fronted by CloudFront and one that is for internal development).

Our production deployment uses Postgres and Apache with `mod_wsgi`. The development one uses nginx and SQLite.
