#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright 2022 Armijn Hemel

import os
import pathlib
import sys

import click
from PIL import Image


@click.command(short_help='Create a PNG representation of a binary file ')
@click.option('--input-file', '-i', 'input_file', required=True,
              help='Input file', type=click.File('rb'))
@click.option('--output-file', '-o', 'output_file', required=True, help='output file',
              type=click.Path(path_type=pathlib.Path))
def main(input_file, output_file):
    binary_data = input_file.read()

    # images have a width and a height. Set the height to 512 bytes.
    height = 512
    width = len(binary_data)//height

    # padding bytes might be needed here TODO

    im = Image.frombuffer("L", (height, width), binary_data, "raw", "L", 0, 1)
    im.save(output_file)


if __name__ == "__main__":
    main()
