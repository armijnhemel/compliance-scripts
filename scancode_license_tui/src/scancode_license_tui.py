#!/usr/bin/env python3

# Licensed under the terms of the Apache license
# SPDX-License-Identifier: Apache-2.0

import collections
import json
import pathlib
import sys

from typing import Any

import click

from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, VerticalScroll
from textual.widgets import DataTable, Footer, Header, Markdown, TextArea, Tree, TabbedContent, TabPane, Input


class ScancodeData():
    '''A representation of the Scancode data'''
    def __init__(self, scancode_results):
        self.scancode_results = scancode_results

    def build_data_set(self):
        scancode_dict = {}
        # convert the scancode results into a dict
        # with the path as the index. TODO: check if
        # can be done differently, as it is only used
        # to decorate the tree.
        parent_to_nodes = {}
        for f in self.scancode_results['files']:
            node_full_name = pathlib.Path(f['path'])

            if node_full_name.parent not in parent_to_nodes:
                parent_to_nodes[node_full_name.parent] = []
            parent_to_nodes[node_full_name.parent].append(node_full_name)
            scancode_dict[node_full_name] = f
        return (scancode_dict, parent_to_nodes)


class ScancodeTree(Tree):
    def build_tree(self, scan_data, results_only):
        '''Build the scancode tree.'''
        self.reset("Scancode results")

        scancode_dict, parent_to_nodes = scan_data

        parent_names = sorted(parent_to_nodes.keys())
        process_deque = collections.deque()

        root = parent_names[0]

        process_deque.append((root, self.root))

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
                    if node_name in scancode_dict:
                        node = parent_node.add_leaf(node_pretty_name, data=scancode_dict[node_name])
                    else:
                        node = parent_node.add_leaf(node_pretty_name)
            except IndexError:
                break

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

        self.result_widget = Markdown()
        self.textarea = TextArea()

    def compose(self) -> ComposeResult:
        # read the scancode results
        with open(self.json_file) as result_file:
            scancode_results = json.load(result_file)

        # store an object with a copy of the data
        scancode_data = ScancodeData(scancode_results)

        # build the tree.
        tree: ScancodeTree[dict] = ScancodeTree('Scancode results')
        tree.show_root = False
        tree.root.expand()
        tree.build_tree(scancode_data.build_data_set(), self.results_only)

        # set properties for the text area
        self.textarea.show_line_numbers = True
        self.textarea.soft_wrap = True

        # Create a table with the results. The root element will
        # not have any associated data with it.
        yield Header()
        with Container(id='app-grid'):
            with Container(id='left-grid'):
                yield Input()
                yield tree
            with TabbedContent(id='tabbed-content'):
                with TabPane('Scancode results'):
                    with VerticalScroll(id='result-area'):
                        yield self.result_widget
                if self.source_directory is not None:
                    with TabPane('Source code'):
                        with VerticalScroll(id='file-area'):
                            yield self.textarea
        yield Footer()

    def on_tree_tree_highlighted(self, event: Tree.NodeHighlighted[None]) -> None:
        pass

    def on_tree_node_selected(self, event: Tree.NodeSelected[None]) -> None:
        '''Display the reports of a node when it is selected'''
        if event.node.data is not None:
            self.result_widget.update(self.build_meta_report(event.node.data))
        else:
            self.result_widget.update('')

    def on_tree_node_collapsed(self, event: Tree.NodeCollapsed[None]) -> None:
        pass

    def build_meta_report(self, result):
        new_markdown = ""
        if result:
            new_markdown += "# Scancode data\n"
            new_markdown += "| | |\n|--|--|\n"
            new_markdown += f"|**Path** | {result['path']}\n"
            new_markdown += f"|**Type** | {result['type']}\n"

            new_markdown += "# Licenses\n"
            new_markdown += "| | |\n|--|--|\n"
            detected_licenses = result.get('detected_license_expression')
            if detected_licenses:
                new_markdown += f"|**Detected licenses** | {detected_licenses}\n"
            else:
                new_markdown += "|**Detected licenses** | \n"

            detected_licenses_spdx = result.get('detected_license_expression_spdx')
            if detected_licenses:
                new_markdown += f"|**Detected licenses (SPDX)** | {detected_licenses_spdx}\n"
            else:
                new_markdown += "|**Detected licenses (SPDX)** | \n"

            new_markdown += f"|**Percentage of license text** | {result['percentage_of_license_text']}\n"

            license_detections = result.get('license_detections', [])
            if license_detections:
                new_markdown += "# License rules\n"
                new_markdown += "|**License** |**SPDX**|**Start line**|**Score**|**Rule**|\n"
                new_markdown += "|--:|--|--|--|--|\n"

                for l in license_detections:
                    for m in l['matches']:
                        new_markdown += f"|{m['license_expression']}|{m['license_expression_spdx']}|{m['start_line']}|{str(m['score'])}|[{m['rule_identifier']}]({m['rule_url']})|\n"

            copyrights = result.get('copyrights', [])
            if copyrights:
                new_markdown += "# Copyrights\n"
                new_markdown += "|**Start line** |**Value**|\n|--:|--|\n"
                for c in copyrights:
                    new_markdown += f"|{c['start_line']}|{c['copyright']}|\n"

            holders = result.get('holders', [])
            if holders:
                new_markdown += "# Holders\n"
                new_markdown += "|**Start line** |**Value**|\n|--:|--|\n"
                for c in holders:
                    new_markdown += f"|{c['start_line']}|{c['holder']}|\n"

            authors = result.get('authors', [])
            if authors:
                new_markdown += "# Authors\n"
                new_markdown += "|**Start line** |**Value**|\n|--:|--|\n"
                copyrights = result.get('authors', [])
                for c in authors:
                    new_markdown += f"|{c['start_line']}|{c['author']}|\n"

        return new_markdown

@click.command(short_help='Interactive Scancode result browser')
@click.option('--result', '-j', required=True, help='Scancode result JSON',
               type=click.Path(path_type=pathlib.Path, exists=True))
@click.option('--source-directory', '-d', help='source code directory',
               type=click.Path(path_type=pathlib.Path, exists=True))
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
            json.load(result_file)
    except:
        print("invalid JSON, exiting.", file=sys.stderr)
        sys.exit(1)

    scancode_app = ScancodeLicenseBrowser(result, source_directory, results_only)
    scancode_app.run()

if __name__ == "__main__":
    main()
