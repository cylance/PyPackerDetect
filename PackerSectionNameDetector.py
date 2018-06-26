from Utils import *
from PackerDetector import *

class PackerSectionNameDetector(PackerDetector):
	def __init__(self, config):
		super().__init__(config)
		self.packerSectionNames = {
			".aspack": "Aspack packer", ".adata": "Aspack packer/Armadillo packer", "ASPack": "Aspack packer", ".ASPack": "ASPAck Protector",
			".boom": "The Boomerang List Builder (config+exe xored with a single byte key 0x77)", ".ccg": "CCG Packer (Chinese Packer)", ".charmve": "Added by the PIN tool", "BitArts": "Crunch 2.0 Packer",
			"DAStub": "DAStub Dragon Armor protector", "!EPack": "Epack packer", "FSG!": "FSG packer (not a section name, but a good identifier)", ".gentee": "Gentee installer",
			"kkrunchy": "kkrunchy Packer", ".mackt": "ImpRec-created section", ".MaskPE": "MaskPE Packer", "MEW": "MEW packer",
			".MPRESS1": "Mpress Packer", ".MPRESS2": "Mpress Packer", ".neolite": "Neolite Packer", ".neolit": "Neolite Packer",
			".nsp1": "NsPack packer", ".nsp0": "NsPack packer", ".nsp2": "NsPack packer", "nsp1": "NsPack packer",
			"nsp0": "NsPack packer", "nsp2": "NsPack packer", ".packed": "RLPack Packer (first section)", "pebundle": "PEBundle Packer",
			"PEBundle": "PEBundle Packer", "PEC2TO": "PECompact packer", "PECompact2": "PECompact packer (not a section name, but a good identifier)", "PEC2": "PECompact packer",
			"pec1": "PECompact packer", "pec2": "PECompact packer", "PEC2MO": "PECompact packer", "PELOCKnt": "PELock Protector",
			".perplex": "Perplex PE-Protector", "PESHiELD": "PEShield Packer", ".petite": "Petite Packer", ".pinclie": "Added by the PIN tool",
			"ProCrypt": "ProCrypt Packer", ".RLPack": "RLPack Packer (second section)", ".rmnet": "Ramnit virus marker", "RCryptor": "RPCrypt Packer",
			".RPCrypt": "RPCrypt Packer", ".seau": "SeauSFX Packer", ".sforce3": "StarForce Protection", ".spack": "Simple Pack (by bagie)",
			".svkp": "SVKP packer", "Themida": "Themida Packer", ".Themida": "Themida Packer", ".taz": "Some version os PESpin",
			".tsuarch": "TSULoader", ".tsustub": "TSULoader", ".packed": "Unknown Packer", "PEPACK!!": "Pepack",
			".Upack": "Upack packer", ".ByDwing": "Upack Packer", "UPX0": "UPX packer", "UPX1": "UPX packer",
			"UPX2": "UPX packer", "UPX!": "UPX packer", ".UPX0": "UPX Packer", ".UPX1": "UPX Packer",
			".UPX2": "UPX Packer", ".vmp0": "VMProtect packer", ".vmp1": "VMProtect packer", ".vmp2": "VMProtect packer",
			"VProtect": "Vprotect Packer", ".winapi": "Added by API Override tool", "WinLicen": "WinLicense (Themida) Protector", "_winzip_": "WinZip Self-Extractor",
			".WWPACK": "WWPACK Packer", ".yP": "Y0da Protector", ".y0da": "Y0da Protector",
		}

	def Run(self, pe, report): # TODO test
		if (not self.config["CheckForPackerSections"]):
			return
		for section in pe.sections:
			try:
				secName = GetCleanSectionName(section)
				if (secName in self.packerSectionNames):
					report.IndicateDetection("Section name '%s' matches known packer: [%s]" % (secName, self.packerSectionNames[secName]))
			except UnicodeDecodeError:
				report.IndicateSuspicion("Section name with invalid characters")