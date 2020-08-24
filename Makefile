APDU_LOGS = $(shell grep -l C-APDU *.txt)
PYTHON_SCRIPT = parseAPDU.py

parse: $(APDU_LOGS:.txt=.html)

%.html: %.txt $(PYTHON_SCRIPT)
	python $(PYTHON_SCRIPT) $< $@
