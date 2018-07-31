from Utils import *
from PackerDetector import *

class LowImportCountDetector(PackerDetector):
	def __init__(self, config):
		super().__init__(config)

	def Run(self, pe, report): # TODO test
		if (not self.config["CheckForLowImportCount"]):
			return
		try:
			importCount = 0
			for library in pe.DIRECTORY_ENTRY_IMPORT:
				if (GetCleanStringFromBytes(library.dll).lower() == "mscoree.dll"):
					return # .NET assembly, counting imports is misleading as they will have a low number
				importCount += len(library.imports)
			if (importCount <= self.config["LowImportThreshold"]):
				report.IndicateDetection("Too few imports (total: %d)" % importCount)
		except AttributeError:
			pass