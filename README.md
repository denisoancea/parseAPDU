# Parse APDU

This is a Python program that parses EMV transaction logs into human-readable HTML files.

## Requirements

* Python 2.7
* [beautifulsoup4](https://pypi.org/project/beautifulsoup4/) package

## Usage

1. Create a log file (with the `.txt` extension), which must satisfy the following:
	* no blank spaces occur in the file name,
	* the APDU commands and responses are written in the same order as they occurred in the transaction,
	* each APDU command is written as `[C-APDU] ` followed by the actual command with no blank spaces,
	* each APDU response is written as `[R-APDU] ` followed by the actual response with no blank spaces.
2. Run `make` which parses each outdated log file into the corresponding `.html` file.

## Acknowledgment

We thank [EFT Lab](https://www.eftlab.com/) for making the EMV tags and their description available.

