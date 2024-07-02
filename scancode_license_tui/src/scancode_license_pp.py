#!/usr/bin/env python3

# Licensed under the terms of the Apache license
# SPDX-License-Identifier: Apache-2.0

import collections
import json
import pathlib
import sys

from typing import Any

import click

from rich.console import Group, group
from rich.panel import Panel
from rich import print_json
from rich.tree import Tree
import rich.table

@group()
def create_license_table(results):
    for r in results:
        result_table = rich.table.Table('', '', title=r['license_expression'], show_lines=True, show_header=False)
        for m in r['matches']:
            result_table.add_row('License expression', m['license_expression'])
            result_table.add_row('License expression (SPDX)', m['spdx_license_expression'])
            result_table.add_row('Start/End lines', f"{m['start_line']} - {m['end_line']}")
            result_table.add_row('Score', str(m['score']))
            result_table.add_row('Rule', m['rule_identifier'])
            result_table.add_row('Rule URL', m['rule_url'])
        yield result_table

def build_meta_report(scancode_result, ignore):
    meta_table = rich.table.Table('', '', title='', show_lines=True, show_header=False)
    #meta_table = rich.table.Table('', '', title=scancode_result['path'], show_lines=True, show_header=False)
    meta_table.add_row('Path', scancode_result['path'])

    # Only files are added to the report, so adding a row for the file type makes little sense
    #meta_table.add_row('Type', scancode_result['type'])

    meta_table.add_row('Detected licenses', scancode_result.get('detected_license_expression', ''))
    meta_table.add_row('Detected licenses (SPDX)', scancode_result.get('detected_license_expression_spdx', ''))

    if not 'detections' in ignore:
        meta_table.add_row('License detections', create_license_table(scancode_result.get('license_detections', [])))

    # if not 'clues' in ignore:
    #    meta_table.add_row('License clues', json.dumps(scancode_result['license_clues']))

    if not 'percentage' in ignore:
        meta_table.add_row('Percentage of license text', str(scancode_result.get('percentage_of_license_text', '')))

    if not 'copyrights' in ignore:
        meta_table.add_row('Copyrights', "\n\n".join([x['copyright'] for x in scancode_result.get('copyrights', [])]))

    if not 'holders' in ignore:
        meta_table.add_row('Holders', "\n\n".join([x['holder'] for x in scancode_result.get('holders', [])]))

    if not 'authors' in ignore:
        meta_table.add_row('Authors', "\n\n".join([x['author'] for x in scancode_result.get('authors', [])]))
    return meta_table

@click.group()
def app():
    pass

@app.command(short_help='Pretty print Scancode result')
@click.option('--result', '-j', required=True, help='Scancode result JSON', type=click.Path(path_type=pathlib.Path, exists=True))
@click.option('--results-only', is_flag=True, help='only show entries with results')
@click.option('--ignore', '-i', multiple=True, type=click.Choice(['authors', 'copyrights', 'detections', 'holders', 'percentage'],
              case_sensitive=False))
def print_results(result, results_only, ignore):
    try:
        with open(result) as result_file:
            scancode_results = json.load(result_file)
    except:
        print("invalid JSON, exiting.", file=sys.stderr)
        sys.exit(1)

    for f in scancode_results['files']:
        if f['type'] == 'directory':
            continue

        if results_only:
            if not (f['authors'] or f['copyrights'] or f['license_detections']):
                continue
        rich.print(build_meta_report(f, ignore))


@app.command(short_help='Pretty print Scancode result tree')
@click.option('--result', '-j', required=True, help='Scancode result JSON',
              type=click.Path(path_type=pathlib.Path, exists=True))
@click.option('--results-only', is_flag=True, help='only show entries with results')
def print_tree(result, results_only):
    try:
        with open(result) as result_file:
            scancode_results = json.load(result_file)
    except:
        print("invalid JSON, exiting.", file=sys.stderr)
        sys.exit(1)

    # convert the scancode results into a dict
    # with the path as the index. TODO: check if
    # can be done differently, as it is only used
    # to decorate the tree.
    scancode_dict = {}

    parent_to_nodes = {}
    for f in scancode_results['files']:
        node_full_name = pathlib.Path(f['path'])

        if node_full_name.parent not in parent_to_nodes:
            parent_to_nodes[node_full_name.parent] = []
        parent_to_nodes[node_full_name.parent].append(node_full_name)
        scancode_dict[node_full_name] = f

    # build the tree.
    tree: Tree[dict] = Tree("Scancode results")

    parent_names = sorted(parent_to_nodes.keys())
    process_deque = collections.deque()

    root = parent_names[0]

    process_deque.append((root, tree))

    while True:
        try:
            # Process each node until there aren't any nodes left.
            # Add the scancode result for each individual file as
            # extra data to the node, except for the root node
            node_name, parent = process_deque.popleft()

            if node_name in parent_to_nodes:
                subtree = Tree(node_name.name)
                parent.add(subtree)
                for n in parent_to_nodes[node_name]:
                    process_deque.append((n, subtree))
            else:
                node_pretty_name = node_name.name

                # only the leaf nodes can contain actual results
                # tag the entries that have any interesting information
                extras = []
                if scancode_dict[node_name].get('authors', []):
                    extras.append(" \U000024b6")
                if scancode_dict[node_name].get('copyrights', []):
                    extras.append(" \U000024b8")
                if scancode_dict[node_name].get('license_detections', []):
                    extras.append(" \U000024c1")

                if extras:
                    node_pretty_name += " ".join(extras)
                else:
                    if results_only:
                        continue

                subtree = Tree(node_pretty_name)
                parent.add(subtree)
        except IndexError:
            break

    rich.print(tree)


if __name__ == "__main__":
    app()
