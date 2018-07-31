import os
import sys

def GetCleanStringFromBytes(bbytes):
	return bbytes.decode("ascii").strip().rstrip('\0')

def GetCleanSectionName(section):
	return GetCleanStringFromBytes(section.Name)

def FormatStringList(strlist):
	return ("'%s'" % "', '".join(strlist))

def DoListsIntersect(l1, l2):
	return len(set(l1) & set(l2)) != 0

def ExtendSysPathRelativeToScript(relpath):
	sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + relpath)

def CmdStrToBool(v):
	if (type(v) == type(True)):
		return v
	elif v.lower() in ('yes', 'true', 't', 'y', '1'):
		return True
	elif v.lower() in ('no', 'false', 'f', 'n', '0'):
		return False
	else:
		raise argparse.ArgumentTypeError('Boolean value expected.')