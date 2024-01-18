export BASE_DN=''
export ADMIN_ID=''
export ADMIN_EMAIL=''
export ADMIN_CN=''
export ADMIN_SN=''
export ADMIN_PASSWD=''
read -p "Base DN: " BASE_DN
read -p "Admin User ID: " ADMIN_ID
read -p "Admin User Email: " ADMIN_EMAIL
read -p "Admin User CN: " ADMIN_CN
read -p "Admin User SN: " ADMIN_SN
read -s -p "Admin Password: " ADMIN_PASSWD

envsubst '$BASE_DN' < auth.template.ldif > auth.ldif
envsubst '$BASE_DN' < pass.template.ldif > pass.ldif
envsubst '$BASE_DN:$ADMIN_ID:$ADMIN_EMAIL:$ADMIN_CN:$ADMIN_SN:$ADMIN_PASSWD' < init.template.ldif > init.ldif

sudo ldapmodify -H ldapi:/// -Y EXTERNAL -f auth.ldif
sudo ldapmodify -H ldapi:/// -Y EXTERNAL -f pass.ldif
sudo ldapadd -H ldapi:/// -Y EXTERNAL -c -f init.ldif

unset BASE_DN
unset ADMIN_ID
unset ADMIN_CN
unset ADMIN_SN
unset ADMIN_PASSWD
rm auth.ldif init.ldif pass.ldif
