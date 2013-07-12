include config.mk

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

keepass-autofill.xpi: check-vars-set nsIKeepassCredentials.xpt nsIKeepass.xpt
	mv *.xpt components/
	rm -f $@
	zip -r $@ *

%.xpt: %.idl
	$(PYTHON2) $(GECKO_SDK_PATH)/sdk/bin/typelib.py -o $@ -I $(GECKO_SDK_PATH)/idl $<

clean:
	rm -f keepass-autofill.xpi components/*.xpt

lint:
	jslint $(JSLINT_OPTIONS) content/browserOverlay.js
