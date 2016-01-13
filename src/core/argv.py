#!/usr/bin/env python
'''
Nmapalayzer
'''
import sys
execfile('core/config.py')
def usage():
	print 'nmapalyzer v1.00\nPlease run software -h switch to see help menu.\n'
	sys.exit(0)
def menu():
	print 'nmapalyzer v1.00\n\n-h\thelp menu\n-i\tinput file\n-m\tselect modes\n\n\na0\tcount connections/ips\na1\tcheck for connections\na2\tshow connections+info\na3\tshow connections+info+data\n\n'
	sys.exit(0)
def wronginput():
	print 'nmapalyzer v1.00\nwrong input, please check menu with -h switch.\n'
def inputanalysis():
	inputs=[]
	n = 0
	for arg in sys.argv:
		n+=1
		if '-i' == arg:
			inputs.append('file:'+str(sys.argv[n]))
		if '-m' == arg:
			inputs.append('mod:'+str(sys.argv[n]))
	if 'file:' not in inputs[0]:
		backup=inputs[1]
		inputs[1]=inputs[0]
		inputs[0]=backup
	return inputs
def checkup():
	argvs = sys.argv
	if len(argvs) is 1:
		usage()
	elif len(argvs) is 2:
		if '-h' == argvs[1]:
			menu()
		else:
			wronginput()
	elif len(argvs) is 5:
		n = 0
		for mod in mods:
			for arg in argvs:
				if mod == arg:
					n+=1
		if n is 1:
			for sw in switches:
				for arg in argvs:
					if sw == arg:
						n+=1
		if n is 3:
			return True
		return False
	else:
		return False
