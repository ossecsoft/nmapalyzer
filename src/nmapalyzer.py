#!/usr/bin/env python
'''
Nmapalayzer
'''
import sys
from core.pyversion import version
from core import compatible
from core import argv
from lib import run
version = version()
compatible.check()
if argv.checkup() is True:
	inputs = argv.inputanalysis()
	fname = inputs[0].rsplit('file:')[1]
	mod = inputs[1].rsplit('mod:')[1]
	run.execute(fname,mod)
else:
	argv.wronginput()
