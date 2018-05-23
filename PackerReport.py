from Utils import *

class PackerReport:
	def __init__(self, name):
		self.name = name
		self.detections = 0
		self.suspicions = 0
		self.failed = False
		self.error = ""
		self.logs = []

	def IndicateDetection(self, message):
		self.logs.append("[DETECTION] %s" % message)
		self.detections += 1

	def IndicateSuspicion(self, message):
		self.logs.append("[SUSPICION] %s" % message)
		self.suspicions += 1

	def IndicateParseFailed(self, message):
		self.error = message
		self.failed = True

	def GetDetections(self):
		return self.detections

	def GetSuspicions(self):
		return self.suspicions

	def GetParseFailed(self):
		return self.failed

	def Print(self, outfn=print):
		outfn("Packer report for: %s" % self.name)
		if (self.failed):
			outfn("\tError: %s" % self.error)
		else:
			outfn("\tDetections: %d" % self.detections)
			outfn("\tSuspicions: %d" % self.suspicions)
			outfn("\tLog:")

			for log in self.logs:
				outfn("\t\t%s" % log)