import ldap from "ldapjs";

export default class LDAP {
	#client = null;
	#basedn = null;
	#peopledn = null;
	#groupsdn = null;

	constructor (url, basedn) {
		const opts = {
			url
		};
		this.#client = new LDAPJS_CLIENT_ASYNC_WRAPPER(opts);
		this.#basedn = basedn;
		this.#peopledn = `ou=people,${basedn}`;
		this.#groupsdn = `ou=groups,${basedn}`;
	}

	async addUser (bind, uid, attrs) {
		const result = await this.#client.bind(bind.dn, bind.password);
		if (!result.ok) {
			return result;
		}
		const userDN = `uid=${uid},${this.#peopledn}`;
		const entry = {
			objectClass: "inetOrgPerson",
			cn: attrs.cn,
			sn: attrs.sn,
			uid,
			userPassword: attrs.userPassword
		};
		return await this.#client.add(userDN, entry);
	}

	async getUser (bind, uid) {
		const result = await this.#client.bind(bind.dn, bind.password);
		if (!result.ok) {
			return result;
		}
		const opts = {
			filter: `(uid=${uid})`,
			scope: "sub"
		};
		return await this.#client.search(this.#peopledn, opts);
	}

	async modUser (bind, uid, attrs) { }

	async delUser (bind, uid) {
		const result = await this.#client.bind(bind.dn, bind.password);
		if (!result.ok) {
			return result;
		}
		const userDN = `uid=${uid},${this.#peopledn}`;
		return await this.#client.del(userDN);
	}

	async addGroup (bind, gid, attrs) {
		const result = await this.#client.bind(bind.dn, bind.password);
		if (!result.ok) {
			return result;
		}
		const groupDN = `cn=${gid},${this.#groupsdn}`;
		const entry = {
			objectClass: "groupOfNames",
			member: "",
			cn: gid
		};
		return await this.#client.add(groupDN, entry);
	}

	async delGroup (bind, gid) {
		const result = await this.#client.bind(bind.dn, bind.password);
		if (!result.ok) {
			return result;
		}
		const groupDN = `cn=${gid},${this.#groupsdn}`;
		return await this.#client.del(groupDN);
	}

	async addUserToGroup (bind, uid, gid) {

	}

	async delUserFromGroup (bind, uid, gid) { }
}

class LDAPJS_CLIENT_ASYNC_WRAPPER {
	#client = null;
	constructor (opts) {
		this.#client = ldap.createClient(opts);
		this.#client.on("error", (err) => {
			console.error(`An error occured:\n${err}`);
		});
		this.#client.on("connectError", (err) => {
			console.error(`Unable to connect to ${opts.url}:\n${err}`);
		});
	}

	bind (dn, password) {
		return new Promise((resolve) => {
			this.#client.bind(dn, password, (err) => {
				if (err) {
					resolve({ ok: false, error: err });
				}
				else {
					resolve({ ok: true });
				}
			});
		});
	}

	add (dn, entry) {
		return new Promise((resolve) => {
			this.#client.add(dn, entry, (err) => {
				if (err) {
					resolve({ ok: false, error: err });
				}
				else {
					resolve({ ok: true });
				}
			});
		});
	}

	search (base, options) {
		return new Promise((resolve) => {
			this.#client.search(base, options, (err, res) => {
				if (err) {
					return resolve({ ok: false, error: err });
				}
				const results = { ok: false, status: 1, message: "", entries: [] };
				res.on("searchRequest", (searchRequest) => { });
				res.on("searchEntry", (entry) => {
					results.entries.push({ dn: entry.pojo.objectName, attributes: entry.pojo.attributes });
				});
				res.on("searchReference", (referral) => { });
				res.on("error", (error) => {
					results.ok = error.status === 0;
					results.status = error.status;
					results.message = error.message;
					resolve(results);
				});
				res.on("end", (result) => {
					results.ok = result.status === 0;
					results.status = result.status;
					results.message = result.message;
					resolve(results);
				});
			});
		});
	}

	modify (name, changes) {
		return new Promise((resolve) => {
			this.#client.modify(name, changes, (err) => {
				if (err) {
					resolve({ ok: false, error: err });
				}
				else {
					resolve({ ok: true });
				}
			});
		});
	}

	del (dn) {
		return new Promise((resolve) => {
			this.#client.del(dn, (err) => {
				if (err) {
					resolve({ ok: false, error: err });
				}
				else {
					resolve({ ok: true });
				}
			});
		});
	}
}
