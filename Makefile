.PHONY: keepass-autofill.xpi

keepass-autofill.xpi:
	rm -f $@
	zip -r $@ *

clean:
	rm -f keepass-autofill.xpi
