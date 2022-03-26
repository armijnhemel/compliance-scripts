#!/usr/bin/env python3

import json
import sys

import click

@click.command(short_help='process CVE data and extract useful data')
#@click.option('--config-file', '-c', required=True, help='configuration file', type=click.File('r'))
@click.option('--log', '-l', 'gitlog', required=True, help='Git log file', type=click.File('r'))
def main(gitlog):

    cur_commit = ''
    cur_commit_msg = []

    commits = []
    try:
        for i in gitlog:
            if i.rstrip().startswith('commit'):
                if cur_commit != '':
                    commit_msg = " ".join(cur_commit_msg).strip()
                    commits.append({'id': cur_commit, 'commit': cur_commit, 'message': commit_msg})
                cur_commit = i.strip()[7:]
                cur_commit_msg = []
            elif i.startswith('Author:'):
                continue
            elif i.startswith('Date:'):
                continue
            else:
                cur_commit_msg.append(i.strip())
    except UnicodeDecodeError:
        # some encoding issue
        pass

    if cur_commit != '':
        commits.append({'id': cur_commit, 'commit': cur_commit, 'message': commit_msg})

    step = 100000

    for i in range(0, len(commits), step):
        print(json.dumps(commits[i:i+step], indent=4))
        break

if __name__ == "__main__":
    main()
