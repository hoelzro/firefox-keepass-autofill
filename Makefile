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

check-vars-set:
	@[[ ! -z "$(GECKO_SDK_PATH)" ]] || (echo "You need to set GECKO_SDK_PATH on the command line or in config.mk"; false)
	@[[ ! -z "$(PYTHON2)" ]] 	|| (echo "You need to set PYTHON2 on the command line or in config.mk"; false)

clean:
	rm -f keepass-autofill.xpi components/*.xpt

lint:
	jslint $(JSLINT_OPTIONS) content/browserOverlay.js
