from Utils import *
from PackerDetector import *

class BadEntryPointSectionDetector(PackerDetector):
	def __init__(self, config):
		super().__init__(config)
		self.acceptableEntrySections = [".text"]
		self.alternativeEntrySections = [".code", "text", ".text0", ".text1", ".text2", ".text3"]
		self.driverEntrySection = ["INIT"]
		self.delphiBssSections = [".BSS", "BSS", ".bss"]
		self.delphiEntrySections = [".itext", "CODE"]

	def Run(self, pe, report): # TODO test
		if (not self.config["CheckForBadEntryPointSections"]):
			return

		entryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
		if (entryPoint == 0):
			report.IndicateSuspicion("Null entry point")
			return

		allSectionNames = []
		entryPointSectionNames = []
		for section in pe.sections:
			try:
				secName = GetCleanSectionName(section)
				allSectionNames.append(secName)
				if (entryPoint >= section.VirtualAddress and entryPoint <= (section.VirtualAddress + section.Misc_VirtualSize)):
					entryPointSectionNames.append(secName)
			except UnicodeDecodeError:
				report.IndicateSuspicion("Section name with invalid characters")

		entryPointSectionCount = len(entryPointSectionNames)
		if (entryPointSectionCount == 0):
			report.IndicateSuspicion("Entry point 0x%x doesn't fall in valid section" % entryPoint)
		else:
			if (entryPointSectionCount > 1):
				report.IndicateDetection("Entry point 0x%x falls in overlapping sections: %s" % (entryPoint, FormatStringList(entryPointSectionNames)))

			if (not DoListsIntersect(self.acceptableEntrySections, entryPointSectionNames)):
				badEpSec = False
				if (DoListsIntersect(self.delphiBssSections, allSectionNames)):
					# has bss, see if we have a delphi ep section
					badEpSec = not DoListsIntersect(self.delphiEntrySections, entryPointSectionNames)
				elif (not DoListsIntersect(self.acceptableEntrySections, allSectionNames)):
					# normal entry section doesn't exist anywhere, so check for alternatives
					badEpSec = not DoListsIntersect(self.alternativeEntrySections, entryPointSectionNames)
				else:
					# not regular ep section, not a delphi entry section, not an alternative entry section, and regular entry section name exists,
					# so the only possibility left is a driver entry section
					badEpSec = not DoListsIntersect(self.driverEntrySection, entryPointSectionNames)

				if (badEpSec):
					report.IndicateDetection("Entry point 0x%x in irregular section(s): %s" % (entryPoint, FormatStringList(entryPointSectionNames)))