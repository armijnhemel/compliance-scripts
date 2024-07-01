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
import rich.table

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Footer, Static, Tree
from textual.widgets.tree import TreeNode

#from textual.logging import TextualHandler

#logging.basicConfig(
    #level="NOTSET",
    #handlers=[TextualHandler()],
#)


class ScancodeLicenseBrowser(App):
    BINDINGS = [
        Binding(key="ctrl+q", action="quit", description="Quit"),
    ]

    CSS_PATH = "scancode_license_tui.css"

    def __init__(self, result, source_directory, results_only, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.json_file = result
        self.source_directory = source_directory
        self.results_only = results_only

    def compose(self) -> ComposeResult:
        # read the scancode results
        with open(self.json_file) as result_file:
            scancode_results = json.load(result_file)

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
        tree.show_root = False
        tree.root.expand()

        parent_names = sorted(parent_to_nodes.keys())
        process_deque = collections.deque()

        root = parent_names[0]

        process_deque.append((root, tree.root))

        while True:
            try:
                # Process each node until there aren't any nodes left.
                # Add the scancode result for each individual file as
                # extra data to the node, except for the root node
                node_name, parent_node = process_deque.popleft()

                if node_name in parent_to_nodes:
                    if node_name in scancode_dict:
                        node = parent_node.add(node_name.name, expand=True, data=scancode_dict[node_name])
                    else:
                        node = parent_node.add(node_name.name, expand=True)
                    for n in parent_to_nodes[node_name]:
                        process_deque.append((n, node))
                else:
                    node_pretty_name = node_name.name

                    # only the leaf nodes can contain actual results
                    # tag the entries that have any interesting information
                    extras = []
                    if scancode_dict[node_name]['authors']:
                        extras.append(" \U000024b6")
                    if scancode_dict[node_name]['copyrights']:
                        extras.append(" \U000024b8")
                    if scancode_dict[node_name]['license_detections']:
                        extras.append(" \U000024c1")

                    if extras:
                        node_pretty_name += " ".join(extras)
                    else:
                        if self.results_only:
                            continue
                    if node_name in scancode_dict:
                        node = parent_node.add_leaf(node_pretty_name, data=scancode_dict[node_name])
                    else:
                        node = parent_node.add_leaf(node_pretty_name)
            except IndexError:
                break

        # Create a table with the results. The root element will
        # not have any associated data with it.
        self.static_widget = Static(Group(self.build_meta_report(None)))
        #self.static_widget2 = Static(Group(self.build_meta_report(None)))

        with Container(id='app-grid'):
            yield tree
            with VerticalScroll(id='result-area'):
                yield self.static_widget
            #if self.source_directory is not None:
                #with VerticalScroll(id='source-code-area'):
                    #yield self.static_widget2
        yield Footer()

    def on_tree_tree_highlighted(self, event: Tree.NodeHighlighted[None]) -> None:
        pass

    def on_tree_node_selected(self, event: Tree.NodeSelected[None]) -> None:
        '''Display the reports of a node when it is selected'''
        if event.node.data is not None:
            self.static_widget.update(Group(self.build_meta_report(event.node.data)))
        else:
            self.static_widget.update()

    def on_tree_node_collapsed(self, event: Tree.NodeCollapsed[None]) -> None:
        pass

    @group()
    def create_license_table(self, results):
        for r in results:
            result_table = rich.table.Table('', '', title=r['license_expression'], show_lines=True, show_header=False)
            for m in r['matches']:
                result_table.add_row('License expression', m['license_expression'])
                result_table.add_row('License expression (SPDX)', m['spdx_license_expression'])
                result_table.add_row('Score', str(m['score']))
                result_table.add_row('Rule', m['rule_identifier'])
                result_table.add_row('Rule URL', m['rule_url'])
            yield result_table

    @group()
    def build_meta_report(self, scancode_result):
        if scancode_result:
            meta_table = rich.table.Table('', '', title='Scancode data', show_lines=True, show_header=False)
            meta_table.add_row('Path', scancode_result['path'])
            meta_table.add_row('Type', scancode_result['type'])
            meta_table.add_row('Detected licenses', scancode_result['detected_license_expression'])
            meta_table.add_row('Detected licenses (SPDX)', scancode_result['detected_license_expression_spdx'])
            meta_table.add_row('License detections', self.create_license_table(scancode_result['license_detections']))
            #meta_table.add_row('License clues', json.dumps(scancode_result['license_clues']))
            meta_table.add_row('Percentage of license text', str(scancode_result['percentage_of_license_text']))
            meta_table.add_row('Copyrights', "\n\n".join([x['copyright'] for x in scancode_result['copyrights']]))
            #meta_table.add_row('Holders', json.dumps(scancode_result['holders']))
            meta_table.add_row('Authors', "\n\n".join([x['author'] for x in scancode_result['authors']]))
            yield meta_table

@click.command(short_help='Interactive Scancode result browser')
@click.option('--result', '-j', required=True, help='Scancode result JSON', type=click.Path(path_type=pathlib.Path, exists=True))
@click.option('--source-directory', '-d', help='source code directory', type=click.Path(path_type=pathlib.Path, exists=True))
@click.option('--results-only', is_flag=True, help='only show entries with results')
def main(result, source_directory, results_only):
    # quick check to see if the JSON data is actually valid
    if source_directory is not None:
        if not source_directory.is_dir():
            print(f"Directory {source_directory} is not a valid directory, exiting.",
                  file=sys.stderr)
            sys.exit(1)
    try:
        with open(result) as result_file:
            scancode_results = json.load(result_file)
    except:
        print("invalid JSON, exiting.", file=sys.stderr)
        sys.exit(1)

    app = ScancodeLicenseBrowser(result, source_directory, results_only)
    app.run()

if __name__ == "__main__":
    main()
