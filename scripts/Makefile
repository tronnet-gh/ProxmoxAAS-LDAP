.PHONY: dev-init

prerequisites:
	@echo "=================== Installing Prerequisites ==================="
	apt install debconf-utils slapd ldap-utils sudo gettext
	git clone https://git.tronnet.net/tronnet/open-ldap-setup
	cd open-ldap-setup/; bash gencert.sh < ../gencert.conf;
	rm -rf open-ldap-setup/

dev-init: prerequisites dev-reinit

dev-reinit:
	@echo "====================== Initializing Slapd ======================"
	cat debconf-slapd.conf | debconf-set-selections
	DEBIAN_FRONTEND=noninteractive dpkg-reconfigure slapd
	git clone https://git.tronnet.net/tronnet/open-ldap-setup
	cd open-ldap-setup/; bash setup.sh < ../setup.conf;
	rm -rf open-ldap-setup/