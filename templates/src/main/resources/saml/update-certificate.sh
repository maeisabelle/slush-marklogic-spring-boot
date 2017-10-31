#!/bin/bash

IDP_HOST=idp.ssocircle.com
IDP_PORT=443
CERTIFICATE_FILE=ssocircle.cert
KEYSTORE_FILE=samlKeystore.jks
KEYSTORE_PASSWORD=samlKeystoreMLPassword
KEYSTORE_DEFAULT_ALIAS=samlDefaultML
KEYSTORE_ALIAS=ssocircle

openssl s_client -host $IDP_HOST -port $IDP_PORT -prexit -showcerts </dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > $CERTIFICATE_FILE
keytool -delete -alias $KEYSTORE_DEFAULT_ALIAS -keystore $KEYSTORE_FILE -storepass $KEYSTORE_PASSWORD
keytool -delete -alias $KEYSTORE_ALIAS -keystore $KEYSTORE_FILE -storepass $KEYSTORE_PASSWORD
keytool -genkeypair -dname "cn=Marklogic, ou=IT, o=ML, c=US" -alias $KEYSTORE_DEFAULT_ALIAS -keypass $KEYSTORE_PASSWORD -keystore $KEYSTORE_FILE -storepass $KEYSTORE_PASSWORD -validity 365 -keyalg  "RSA"
keytool -import -alias $KEYSTORE_ALIAS -file $CERTIFICATE_FILE -keystore $KEYSTORE_FILE -storepass $KEYSTORE_PASSWORD -noprompt

rm $CERTIFICATE_FILE