JSLINT_OPTIONS = \
    --browser \
    --es5 \
    --maxlen=80 \
    --sloppy \
    --white \
    --predef=KeepassAutofill \
    --predef=Components \
    --vars \
    --plusplus \
    $(NULL)

.PHONY: keepass-autofill.xpi

keepass-autofill.xpi:
	rm -f $@
	zip -r $@ *

clean:
	rm -f keepass-autofill.xpi

lint:
	jslint $(JSLINT_OPTIONS) content/browserOverlay.js
