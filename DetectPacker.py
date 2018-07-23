from Utils import *
ExtendSysPathRelativeToScript('/deps/libpefile')

import pefile
import argparse
from PackerReport import *
from PEIDDetector import *
from LowImportCountDetector import *
from PackerSectionNameDetector import *
from BadEntryPointSectionDetector import *
from NonStandardSectionNameDetector import *

DEFAULT_CONFIG = {
	"LowImportThreshold": 10,
	"NonStandardSectionThreshold": 3,
	"BadSectionNameThreshold": 2,
	"OnlyPEIDEntryPointSignatures": True,
	# large database has more than 3x as many signatures, but many are for non-packers
	# and will create false positives. we can move signatures from the long list to the short
	# list as needed, though.
	"UseLargePEIDDatabase": False,

	"CheckForPEIDSignatures": True,
	"CheckForBadEntryPointSections": True,
	"CheckForLowImportCount": True,
	"CheckForPackerSections": True,
	"CheckForNonStandardSections": True
}

def InitializeDetectors(config):
	return [
		PEIDDetector(config),
		BadEntryPointSectionDetector(config),
		LowImportCountDetector(config),
		PackerSectionNameDetector(config),
		NonStandardSectionNameDetector(config)
	]


def CheckForPackersInMemory(filedata, config=DEFAULT_CONFIG):
	detectors = InitializeDetectors(config)

	report = PackerReport(filedata)
	pe = pefile.PE(data=filedata)
	for detector in detectors:
		detector.Run(pe, report)
	return report

def CheckForPackers(files, config=DEFAULT_CONFIG):
	detectors = InitializeDetectors(config)

	reports = {}
	for file in files:
		report = PackerReport(file)
		try:
			pe = pefile.PE(file)
			for detector in detectors:
				detector.Run(pe, report)
		except FileNotFoundError:
			report.IndicateParseFailed("file not found")
		finally:
			reports[file] = report
	return reports


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Detect if a Windows PE file is packed', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
	for name, value in DEFAULT_CONFIG.items():
		if (type(value) == type(True)):
			parser.add_argument("--" + name, metavar='<bool>', type=CmdStrToBool, nargs=1, default=value, help=" ")
		elif (type(value) == type(1)):
			parser.add_argument("--" + name, metavar='<number>', type=int, nargs=1, default=value, help=" ")

	parser.add_argument("filenames", metavar='file', type=str, nargs='+', help='File(s) to process')
	args = parser.parse_args()

	config = {}
	for name, value in DEFAULT_CONFIG.items():
		if (name in args.__dict__):
			val = args.__dict__[name]
			if (type(val) == type(list())):
				val = val[0]
			config[name] = val
		else:
			config[name] = value

	reports = CheckForPackers(args.filenames, config)
	for file, report in reports.items():
		report.Print()

"""
	reports = CheckForPackers(['C:\\Code\\PyPackerDetect\\testfiles\\procexp_mimic_delphi.exe'])
	for file, report in reports.items():
		report.Print()
"""