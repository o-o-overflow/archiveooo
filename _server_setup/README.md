## Suggested setup

1. `adduser archiveooo`. You can also have `periodic_archiveooo` and `runner_archiveooo` users with limited file access.

2. Checkout the code in `/home/archiveooo/archiveooo`

3. Create the `/home/archiveooo/archiveooo/env` virtualenv with [requirements.txt](../requirements.txt) 

4. Create your `/home/archiveooo/archiveooo/archiveooo/local_settings_outside_git.py` -- see the [example](./sample_local_settings_outside_git.py)

5. Create the Postgres database and user (or use the default local SQLite). Default Ubuntu settings should be fine.

6. Setup AWS EC2. You can have separate accounts for the main site and the periodic cleaner. See the code for what the scripts do -- note that currently we support only one region, something the permissions should also enforce.

7. Setup the non-cloudfronted website. Expose static files (for instance, link `/home/archiveooo/archiveooo/ctfoood/static/` to `/var/www/html/static`). See the sample files in this folder.

8. Create an S3 bucket to host public files. Otherwise, create `dockerimg` and `public_files` folders and link them in `/var/www/html/`.

9. Setup the periodic cleanup scripts: [periodic_archiveooo.crontab](./periodic_archiveooo.crontab) and [weekly_docker_cleanup](./weekly_docker_cleanup).

10. Optionally, create accounts for Dockerhub and reCAPTCHA.

11. Optionally, setup email sending. In production, we use Postfix setup to talk to Amazon SES.

12. Optionally, setup AWS CloudFront. Our setup uses Origin cache headers (see the setup in `views.py` and in apache files), forwards all cookies and query strings.
