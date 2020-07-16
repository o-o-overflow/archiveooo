#!/usr/bin/env python3

import argparse
import logging
import shlex
import subprocess
import sys

import os.path
SOURCE_DIR = os.path.dirname(os.path.abspath(__file__))


#logging.basicConfig(level="WARNING")  # boto3 / urllib3 still show debug logs?
logger = logging.getLogger("OOO")
logger.setLevel("DEBUG")
try:
    import coloredlogs
    coloredlogs.install(logger=logger, level="DEBUG")
except ImportError:
    pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("format", help="Like: dc2020q")
    parser.add_argument("challs_file", type=argparse.FileType())
    parser.add_argument("--log-level", metavar='LEVEL', default="DEBUG", help="Default: DEBUG")
    parser.add_argument("--run-tester", action='store_true', help="run ./tester")
    parser.add_argument("--live-output", action='store_true')
    args = parser.parse_args()

    if args.log_level:
        logger.setLevel(args.log_level)

    assert args.format in ('dc2018q', 'dc2018f', 'dc2019q', 'dc2019f', 'dc2020q', 'dc2020f')

    imported = []; failed = []
    for l in args.challs_file:
        chalname = l.strip().split(',')[0]
        if chalname.startswith('#') or not chalname: continue

        if args.format == 'dc2018q':
            pull_from = f'git@github.com:o-o-overflow/chall-{chalname}.git'
        else:
            pull_from = f'git@github.com:o-o-overflow/{args.format}-{chalname}.git'

        cmd = ['./import.py', '--format', args.format ]  # Should be necessary only for dc2018
        if args.log_level: cmd += ['--log-level', args.log_level]
        if args.run_tester: cmd += ['--run-tester']
        cmd += ['--create-chal', '--accept-unclean', chalname, pull_from]

        cmds = ' '.join(shlex.quote(x) for x in cmd) + " 2>&1"
        logger.info("[*] Will run %s ...", cmds)
        outname = os.path.join(os.path.abspath(os.getcwd()), f"{chalname}.out")
        if args.live_output:
            p = subprocess.run(['script','--return', '-q', '-c', cmds, outname],
                    cwd=SOURCE_DIR, universal_newlines=True)
        else:
            p = subprocess.run(cmd,
                    cwd=SOURCE_DIR, universal_newlines=True,
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            with open(outname, 'w') as of:
                of.write(p.stdout)

            # XXX: copied from run_tester_cmd
            tester_output = '\n'.join(l for l in p.stdout.splitlines() \
                    if ('WARNING Public file:' not in l) \
                    and ('PLEASE VERIFY THAT THE PUBLIC FILES ARE CORRECT' not in l) \
                    and ('PLEASE VERIFY THAT THIS IS CORRECT: files in public bundle:' not in l))

            tester_gave_errors = any(x in tester_output for x in \
                    ('CRITICAL', 'ERROR', 'EXCEPTION', 'AssertError'))
            tester_gave_warnings = ('WARNING ' in tester_output)

            if tester_gave_errors:
                logger.error("import gave 1+ errors for %s", chalname)
            if tester_gave_warnings:
                logger.error("import gave 1+ warnings for %s", chalname)


        if p.returncode != 0:
            logger.critical("Failed for %s (returncode %d)", chalname, p.returncode)
            failed.append(chalname)
        else:
            logger.debug("import.py succeeded for %s", chalname)
            imported.append(chalname)

    logger.info("Summary: imported: %s", ' '.join(imported))
    logger.info("Summary: failed: %s", ' '.join(failed))
    return 0 if (bool(imported) and not bool(failed)) else 1


if __name__ == "__main__":
    sys.exit(main())
