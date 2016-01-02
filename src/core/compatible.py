#!/usr/bin/env python
'''
Nmapalayzer
'''
import sys
import os
from core.pyversion import version
def check():
    if 'linux' in sys.platform:
        os.system('clear')
	#elif 'darwin' == sys.platform:
	#	os.system('clear')
    #elif 'win32' == sys.platform or 'win64' == sys.platform:
    #    os.system('cls')
    else:
        sys.exit('Sorry, This version of software just could be run on linux')
    if version() is 2:
        pass
	if version() is 3:
		sys.exit('this script is not test with python 3 yet,please use 2.x.')
    else:
        sys.exit('Your python version is not supported!')
    return