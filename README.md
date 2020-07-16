Largely built to archive CTF challenges -- in other words, to play at one's own leisure without time pressure.

Challenge data resides in a Django-managed database for now, but we'd gladly accept issues for data too (for instance, hints and extra notes on existing challenges).

Brought to you with love from the <a href="https://oooverflow.io">Order of the Overflow</a>, current host of *the* <a href="https://defcon.org">DEF CON</a> CTF.

----

Base structure: Chal -> ChalCheckout(s) -> VM(s) / containers

What is public is one main checkout for each challenge. The archive shows that ChalCheckout (ideally, straight out of `./import.py`) + data from the base Chal (an extra description, additional tags, point value, links, hints, ...).

The Django admin interface serves as the main editor + a private per-challenge page that can be used to auto-pull a new checkout from git.

Checkouts are independent from each other, files included, and there can be multiple public ones reachable via direct URLs. Checkouts are private by default, to ease testing. S3 URLs are unpredictable, but do not require logins.

The code is not super-clean, but it's not that dirty either. There are special Tags and Achievements though: for instance, speedrun-tagged challenges get a special message.

