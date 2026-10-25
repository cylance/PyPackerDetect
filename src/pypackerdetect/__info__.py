# -*- coding: UTF-8 -*-
"""PyPackerDetect package information.

"""
import os
from datetime import datetime

__y = str(datetime.now().year)
__s = "2018"

__author__    = "Nick Cano"
__credits__   = "Alexandre D'Hondt"
__copyright__ = "© {} Cylance".format([__y, __s + "-" + __y][__y != __s])
__license__   = "GPLv3 (https://www.gnu.org/licenses/gpl-3.0.fr.html)"
__reference__ = "https://github.com/cylance/PyPackerDetect"
__source__    = "https://github.com/packing-box/pypackerdetect"

with open(os.path.join(os.path.dirname(__file__), "VERSION.txt")) as f:
    __version__ = f.read().strip()

