from Utils import *
from PackerDetector import *

class NonStandardSectionNameDetector(PackerDetector):
	def __init__(self, config):
		super().__init__(config)
		self.knownSectionNames = [
			".00cfg", ".arch", ".autoload_text", ".bindat", ".bootdat", ".bss", ".BSS",
			".buildid", ".CLR_UEF", ".code", ".cormeta", ".complua", ".CRT", ".cygwin_dll_common",
			".data", ".DATA", ".data1", ".data2", ".data3", ".debug", ".debug$F",
			".debug$P", ".debug$S", ".debug$T", ".drectve ", ".didat", ".didata", ".edata",
			".eh_fram", ".export", ".fasm", ".flat", ".gfids", ".giats", ".gljmp",
			".glue_7t", ".glue_7", ".idata", ".idlsym", ".impdata", ".itext", ".ndata",
			".orpc", ".pdata", ".rdata", ".reloc", ".rodata", ".rsrc", ".sbss",
			".script", ".shared", ".sdata", ".srdata", ".stab", ".stabstr", ".sxdata",
			".text", ".text0", ".text1", ".text2", ".text3", ".textbss", ".tls",
			".tls$", ".udata", ".vsdata", ".xdata", ".wixburn", ".wpp_sf ", "BSS",
			"CODE", "DATA", "DGROUP", "edata", "idata", "INIT", "minATL",
			"PAGE", "rdata", "sdata", "shared", "Shared", "testdata", "text"
		]


	def Run(self, pe, report): # TODO test
		if (not self.config["CheckForNonStandardSections"]):
			return
		unknownSections = []
		for section in pe.sections:
			secName = GetCleanSectionName(section)
			if (secName not in self.knownSectionNames):
				unknownSections.append(secName)

		unknownSectionCount = len(unknownSections)
		if (unknownSectionCount >= self.config["NonStandardSectionThreshold"]):
			report.IndicateDetection("Detected %d non-standard sections: %s" % (unknownSectionCount, FormatStringList(unknownSections)))
