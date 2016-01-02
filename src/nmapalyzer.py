#!/usr/bin/env python
'''
Nmapalayzer
'''
import argparse
from core.pyversion import version
from core import compatible
parser = argparse.ArgumentParser()
parser.add_argument('-f', '--file', dest='input_file', default='captured.pcap')
parser.add_argument('-o', '--output', dest='output_file', default='result.html')
data = parser.parse_args()
version = version()
compatible.check()


