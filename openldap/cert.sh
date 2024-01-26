# requires gnutls-bin ssl-cert

export CA_FILE
export CERT_FILE
export KEY_FILE

read -p "CA Cert File Path: " CA_FILE
read -p "Server Cert File Path: " CERT_FILE
read -p "Server Key File Path: " KEY_FILE

envsubst '$CA_FILE:$CERT_FILE:$KEY_FILE' < cert.template.ldif > cert.ldif

sudo ldapmodify -Y EXTERNAL -H ldapi:/// -f cert.ldif

rm cert.ldif

unset CA_FILE
unset CERT_FILE
unset KEY_FILE