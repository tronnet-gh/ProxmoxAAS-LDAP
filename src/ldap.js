import ldap from "ldapjs";
import { exit } from "process";

export class LDAP {
	#client = null;
	#paasBind = null;
	#baseDN = null;

	constructor (url, paasBind, baseDN) {
		const opts = {
			url
		};
		this.#client = ldap.createClient(opts);
		this.#client.on("connectError", (err) => {
			console.err(`Error: could not establish connection to ${url}`);
			console.err(err);
			exit(1);
		});

		this.#paasBind = paasBind;
		this.#baseDN = baseDN;
	}

	addUser (uid, entry) {}

	getUser (uid) {}

	modUser (uid, entry) {}

	delUser (uid) {}
}
