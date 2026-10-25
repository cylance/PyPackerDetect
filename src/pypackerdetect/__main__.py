# -*- coding: UTF-8 -*-
import logging
from argparse import ArgumentParser, ArgumentTypeError, RawTextHelpFormatter
from ast import literal_eval
from os.path import isfile
from pefile import PEFormatError
from time import perf_counter

from .__info__ import __author__, __credits__, __copyright__, __license__, __reference__, __source__, __version__
from .__init__ import PyPackerDetect


def valid_file(path):
    if not isfile(path):
        raise ArgumentTypeError(f"input file does not exist: {path}")
    return path


class PositiveInt:
    def __call__(self, string):
        try:
            n = literal_eval(string)
        except (SyntaxError, ValueError):
            raise ArgumentTypeError(f"invalid positive int value: '{string}'")
        if not isinstance(n, int) or n < 0:
            raise ArgumentTypeError(f"invalid positive int value: '{string}'")
        return int(n)
    
    def __repr__(self):
        return "positive int"


def main():
    """ Tool's main function """
    descr = "PyPackerDetect {}\n\nAuthor   : {}\nCredits  : {}\nCopyright: {}\nLicense  : {}\nReference: {}\n" \
            "Source   : {}\n\nThis tool applies multiple checks for determining if a PE file is packed or not and " \
            "reports the related findings, either as suspicions or detections.\n\n"
    descr = descr.format(__version__, __author__, __credits__, __copyright__, __license__, __reference__, __source__)
    examples = "usage examples:\n- " + "\n- ".join([
        "pypackerdetect program.exe",
        "pypackerdetect program.exe -b",
        "pypackerdetect program.exe --low-imports --unknown-sections   # disable these two checks",
        "pypackerdetect program.exe --imports-threshold 5 --bad-sections-threshold 5",
        "pypackerdetect program.exe --peid-db-path user_db.txt --sections-json sections.json",
    ])
    parser = ArgumentParser(description=descr, epilog=examples, formatter_class=RawTextHelpFormatter, add_help=False)
    parser.add_argument("path", type=valid_file, help="path to the portable executable")
    pths = parser.add_argument_group("path arguments")
    pths.add_argument("--packers-json", metavar="JSON", help="path to the JSON with common packer section names "
                                                             "(default: package-embedded JSON)")
    pths.add_argument("--peid-db-path", metavar="TXT_DB",
                      help="path to the PEiD database to be used (default: package-embedded DB)")
    pths.add_argument("--sections-json", metavar="JSON", help="path to the JSON with known section names "
                                                              "(default: package-embedded JSON)")
    opt = parser.add_argument_group("optional arguments")
    opt.add_argument("--bad-ep-sections", action="store_false",
                     help="disable the check for bad entry point sections (enabled by default)")
    opt.add_argument("--low-imports", action="store_false",
                     help="disable the check for a low number of imports (enabled by default)")
    opt.add_argument("--packer-sections", action="store_false",
                     help="disable the check for known packer section names (enabled by default)")
    opt.add_argument("--peid", action="store_false", help="disable detection with PEiD (enabled by default)")
    opt.add_argument("--peid-ep-only", action="store_false",
                     help="disable entry point-only matching for PEiD, scanning the whole file instead (default: False)")
    opt.add_argument("--peid-large-db", action="store_true", help="use the large database for PEiD (default: False)")
    opt.add_argument("--unknown-sections", action="store_false",
                     help="disable the check for unknown section names (enabled by default)")
    thrs = parser.add_argument_group("threshold arguments")
    thrs.add_argument("--bad-sections-threshold", dest="bad_sections_threshold", metavar="N", type=PositiveInt(),
                      default=2, help="threshold for the number of bad sections (default: 2)")
    thrs.add_argument("--imports-threshold", dest="import_threshold", metavar="N", type=PositiveInt(), default=10,
                      help="threshold for the minimum number of imports (default: 10)")
    thrs.add_argument("--unknown-sections-threshold", dest="unknown_sections_threshold", metavar="N",
                      type=PositiveInt(), default=3, help="threshold for the number of unknown sections (default: 3)")
    extra = parser.add_argument_group("extra arguments")
    extra.add_argument("-b", "--benchmark", action="store_true",
                       help="enable benchmarking, output in seconds (default: False)")
    extra.add_argument("-h", "--help", action="help", help="show this help message and exit")
    extra.add_argument("-v", "--verbose", action="store_true", help="display debug information (default: False)")
    args = parser.parse_args()
    logging.basicConfig()
    args.logger = logging.getLogger("pypackerdetect")
    args.logger.setLevel([logging.INFO, logging.DEBUG][args.verbose])
    code = 0
    # execute the tool
    if args.benchmark:
        t1 = perf_counter()
    try:
        r = PyPackerDetect(**vars(args)).detect(args.path)
        dt = str(perf_counter() - t1) if args.benchmark else ""
        PyPackerDetect.report(args.path, r)
        if dt != "":
            print(dt)
    except PEFormatError as e:
        args.logger.error(f"Not a valid PE file ({e.value})")
        code = 1
    except Exception as e:
        args.logger.exception(e)
        code = 1
    return code

