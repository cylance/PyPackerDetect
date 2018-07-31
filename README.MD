# PyPackerDetect

A small python script/library to detect whether an executable is packed.

This is one of many tools we use for dataset curation within the ARG team at Cylance. Accuracy is not perfect, but is sufficient in accomplishing what we need.

Tested and devloped using Python 3.

[pefile](https://github.com/erocarrera/pefile) is used for PE parsing, found in `./deps/libpefile`.

PEID Signatures are also used. There are two signature collections compiled from multiple online sources, found in `./deps/peid`.

Multiple other hueristics are used for detection, and those are found in `*Detector.py` files, with the base class in `PackerDetector.py`.

## Usage

Example usage is in `DetectPacker.py`. Can be run via command line.

## Detection Mechanisms

- PEID signatures
- Known packer section names
- Entrypoint in non-standard section
- Threshhold of non-standard sections reached
- Low number of imports
- Overlapping entrypoint sections

## Resources

Big thanks to [Hexacorn](http://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/), a good portion of the known PE section names come from there.