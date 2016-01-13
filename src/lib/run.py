#!/usr/bin/env python
'''
Nmapalayzer
'''
import a0
import a1
import a2
import a3
import sys
def execute(fname,mod):
	try:
		f = open(fname)
		f.close()
	except:
		sys.exit('nmapalyzer v1.00\ncann\'t find the file')
	if mod == 'a0':
		a0.run(fname)
	elif mod == 'a1':
		a1.run(fname)
	elif mod == 'a2':
		a2.run(fname)
	elif mod == 'a3':
		a3.run(fname)
	
