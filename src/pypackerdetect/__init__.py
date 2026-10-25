# -*- coding: UTF-8 -*-
import json
import os
import peid
import re
from functools import lru_cache
from pefile import PE


__all__ = ["PyPackerDetect"]


@lru_cache
def _real_section_names(path, logger=None, timeout=10):
    from subprocess import Popen, PIPE, TimeoutExpired
    try:
        p, names = Popen(["objdump", "-h", path], stdout=PIPE, stderr=PIPE), []
    except OSError as e:  # e.g. objdump is not installed
        if logger:
            logger.debug(f"objdump: {e}")
        return
    try:
        out, err = p.communicate(timeout=timeout)
    except TimeoutExpired:
        p.kill()
        p.communicate()
        if logger:
            logger.debug(f"objdump: timeout ({timeout} seconds)")
        return
    if err:
        if logger:
            for l in err.decode("latin-1").strip().split("\n"):
                logger.debug(l)
        return
    for l in out.decode("latin-1").strip().split("\n"):
        m = re.match(r"\s+\d+\s(.*?)\s+", l)
        if m:
            names.append(m.group(1))
    return names


class PyPackerDetect:
    def __init__(self, peid=True, peid_large_db=False, peid_ep_only=True, peid_db_path=None, bad_ep_sections=True,
                 low_imports=True, packer_sections=True, unknown_sections=True, import_threshold=10,
                 unknown_sections_threshold=3, bad_sections_threshold=2, logger=None, packers_json=None,
                 sections_json=None, **kwargs):
        """ Configure the detector with various parameters. """
        _p = lambda f: os.path.join(os.path.dirname(__file__), "db", f)
        self.__config = {
            'peid_large_db': peid_large_db, 'peid_ep_only': peid_ep_only, 'packer_sections': packer_sections,
            'peid': peid, 'bad_ep_sec': bad_ep_sections, 'low_imports': low_imports, 'unknown_sec': unknown_sections,
            'peid_db_path': os.path.abspath(peid_db_path) if peid_db_path is not None else \
                            _p("sigs_long.txt") if peid_large_db else _p("sigs_short.txt"),
            'packers_json': os.path.abspath(packers_json) if packers_json is not None else _p("packers.json"),
            'sections_json': os.path.abspath(sections_json) if sections_json is not None else _p("sections.json"),
        }
        if logger:
            logger.debug(f"JSON with common packer section names: {self.__config['packers_json']}")
        with open(self.__config['packers_json']) as f:
            self.__config['packers_json'] = json.load(f)['packers']
        if logger:
            logger.debug(f"JSON with known section names: {self.__config['sections_json']}")
        with open(self.__config['sections_json']) as f:
            self.__config['sections_json'] = json.load(f)['sections']
        self.__thresholds = {
            'bad_sections':     bad_sections_threshold,
            'imports':          import_threshold,
            'unknown_sections': unknown_sections_threshold,
        }
        self.logger = logger
    
    def detect(self, pe):
        """ Analyze the input PE file (path or pefile.PE instance) for suspicions and/or detections of packers. """
        if not isinstance(pe, PE):
            path = pe
            pe = PE(path)
            pe.path = path
        if getattr(pe, "path", None) is None:
            # a PE instance parsed from a buffer has no path while PEiD and objdump work on files ; use a temporary copy
            from tempfile import NamedTemporaryFile
            with NamedTemporaryFile(suffix=".exe", delete=False) as f:
                f.write(pe.__data__)
            pe.path = f.name
            try:
                return self.detect(pe)
            finally:
                pe.path = None
                os.remove(f.name)
        r = {'detections': [], 'suspicions': []}
        def __add(i, msg):
            if self.logger:
                self.logger.debug("%s:%s" % (['DETECTION', 'SUSPICION'][i], msg))
            r[['detections', 'suspicions'][i]].append(msg)
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        # parse the input PE file
        d = {'all': [], 'bad': [], 'ep': [], 'packer': [], 'unknown': []}
        for i, s in enumerate(pe.sections):
            try:
                n = s.Name.decode("ascii").strip().rstrip("\0 ")
                # special case: for some executables compiled with debug information, some sections may be named with
                #                the format "/[N]" where N is the offset in the string table ; in this case, we compute
                #                the real section names and map them to the shortened ones to compare the relevant names
                #                with the database of known section names
                if re.match(r"^\/\d+$", n) and (rsn := _real_section_names(pe.path, logger=self.logger)) and \
                   i < len(rsn):
                    n = rsn[i]
                d['all'].append(n)
                # the loader uses SizeOfRawData when VirtualSize is null ; the upper bound is excluded as it is the start
                #  of the next section for contiguous sections
                if s.VirtualAddress <= ep < s.VirtualAddress + (s.Misc_VirtualSize or s.SizeOfRawData):
                    d['ep'].append(n)
                if n not in self.__config['sections_json']['known']:
                    d['unknown'].append(n)
                p = self.__config['packers_json'].get(n)
                # even if found in the packers database, ensure the related section name does not clash with a known one
                if p is not None and n not in self.__config['sections_json']['known']:
                    d['packer'].append(n)
            except UnicodeDecodeError:
                d['bad'].append(s.Name.decode('latin1').strip().rstrip("\0 "))
                __add(1, "Section name with invalid characters")
        # bad entry point sections
        __intersect = lambda l1, l2: len(set(l1).intersection(l2)) > 0
        if self.__config['bad_ep_sec']:
            ep_sec_list = "', '".join(d['ep'])
            if ep == 0:
                __add(1, "Null entry point")
            l_ep = len(d['ep'])
            if l_ep == 0:
                __add(0, "Entry point 0x%x does not fall in any section" % ep)
            else:
                if l_ep > 1:
                    __add(0, "Entry point 0x%x falls in overlapping sections: '%s'" % (ep, ep_sec_list))
                if not __intersect(self.__config['sections_json']['acceptable'], d['ep']):
                    bad_ep_sec = False
                    if __intersect(self.__config['sections_json']['delphi-bss'], d['all']):
                        # has bss, see if we have a delphi ep section
                        bad_ep_sec = not __intersect(self.__config['sections_json']['delphi'], d['ep'])
                    elif not __intersect(self.__config['sections_json']['acceptable'], d['all']):
                        # normal entry section doesn't exist anywhere, so check for alternatives
                        bad_ep_sec = not __intersect(self.__config['sections_json']['alternative'], d['ep'])
                    else:
                        # not regular ep section, not a delphi entry section, not an alternative entry section, and
                        #  regular entry section name exists, so the only possibility left is a driver entry section
                        bad_ep_sec = not __intersect(self.__config['sections_json']['driver'], d['ep'])
                    if bad_ep_sec:
                        __add(0, "Entry point 0x%x in irregular section(s): '%s'" % (ep, ep_sec_list))
        # low import count
        if self.__config['low_imports']:
            c = 0
            try:
                for lib in pe.DIRECTORY_ENTRY_IMPORT:
                    if lib.dll.decode("latin-1").strip().rstrip("\0").lower() == "mscoree.dll":
                        c = -1  # .NET assembly, counting imports is misleading as they will have a low number
                        break
                    c += len(lib.imports)
            except AttributeError:  # no import directory
                pass
            if (0 <= c <= self.__thresholds['imports']):
                __add(0, "Too few imports (total: %d)" % c)
        # non standard sections
        if self.__config['unknown_sec']:
            u = len(d['unknown'])
            un_sec_list = "', '".join(d['unknown'])
            if u >= self.__thresholds['unknown_sections']:
                __add(0, "Detected %d non-standard sections: '%s'" % (u, un_sec_list))
            if len(d['bad']) >= self.__thresholds['bad_sections']:
                __add(0, "Detected %d sections with invalid names" % len(d['bad']))
        # packer sections
        if self.__config['packer_sections']:
            for n in d['packer']:
                __add(0, "Section name '%s' matches known packer: [%s]" % (n, self.__config['packers_json'][n]))
        # apply PEiD
        if self.__config['peid']:
            for m in peid.identify_packer(pe.path, db=self.__config['peid_db_path'],
                                          ep_only=self.__config['peid_ep_only'], logger=self.logger):
                if len(m[1] or []) > 0:
                    __add(0, "Found PEID signature: %s" % ", ".join(m[1]))
        return r
    
    @staticmethod
    def report(pe, findings):
        """ Report findings like the original project. """
        print("Packer report for: %s" % (getattr(pe, "path", "unknown path") if isinstance(pe, PE) else pe))
        print("\tDetections: %d" % len(findings['detections']))
        print("\tSuspicions: %d" % len(findings['suspicions']))
        if len(findings['detections']) > 0 or len(findings['suspicions']) > 0:
            print("\tLog:")
            for d in findings['detections']:
                print("\t\t[DETECTION] %s" % d)
            for s in findings['suspicions']:
                print("\t\t[SUSPICION] %s" % s)

