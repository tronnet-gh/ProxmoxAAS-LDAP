export BASE_DN=''
read -p "Base DN: " BASE_DN

export PAAS_PASSWD=$(tr -dc 'A-Za-z0-9!"#$%&'\''()*+,-./:;<=>?@[\]^_`{|}~' </dev/urandom | head -c 256; echo)
echo "$PAAS_PASSWD" -n > paas.token
echo "Saved PAAS Authentication Token (password) to paas.token"

envsubst '$BASE_DN' < auth.template.ldif > auth.ldif
envsubst '$BASE_DN' < pass.template.ldif > pass.ldif
envsubst '$BASE_DN:$PAAS_PASSWD' < init.template.ldif > init.ldif

sudo ldapmodify -H ldapi:/// -Y EXTERNAL -f auth.ldif
sudo ldapmodify -H ldapi:/// -Y EXTERNAL -f pass.ldif
sudo ldapadd -H ldapi:/// -Y EXTERNAL -c -f init.ldif

unset BASE_DN
unset PAAS_PASSWD
rm auth.ldif init.ldif pass.ldif
