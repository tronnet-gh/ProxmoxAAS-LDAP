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

	async bindUser (uid, password) {
		return await this.#client.bind(`uid=${uid},${this.#peopledn}`, password);
	}

	async getAllUsers () {
		const result = await this.#client.search(this.#peopledn, {
			scope: "one"
		});
		result.users = result.entries;
		return result;
	}

	async addUser (uid, attrs) {
		const userDN = `uid=${uid},${this.#peopledn}`;
		if (!attrs.cn || !attrs.sn || !attrs.userPassword) {
			return {
				ok: false,
				error: {
					code: 100,
					name: "UndefinedAttributeValueError",
					message: "Undefined Attribute Value"
				}
			};
		}
		const entry = {
			objectClass: "inetOrgPerson",
			cn: attrs.cn,
			sn: attrs.sn,
			uid,
			userPassword: attrs.userPassword
		};
		return await this.#client.add(userDN, entry);
	}

	async getUser (uid) {
		const result = await this.#client.search(`uid=${uid},${this.#peopledn}`, {});
		result.user = result.entries[0]; // assume there should only be 1 entry
		return result;
	}

	async modUser (uid, newAttrs) {
		const logger = new LDAP_MULTIOP_LOGGER(`modify ${uid}`);
		for (const attr of ["cn", "sn", "userPassword"]) {
			if (attr in newAttrs && newAttrs[attr]) { // attr should exist and not be undefined or null
				const change = new ldap.Change({
					operation: "replace",
					modification: {
						type: attr,
						values: [newAttrs[attr]]
					}
				});
				await this.#client.modify(`uid=${uid},${this.#peopledn}`, change, logger);
			}
		}
		return logger;
	}

	async delUser (uid) {
		const logger = new LDAP_MULTIOP_LOGGER(`del ${uid}`);
		const userDN = `uid=${uid},${this.#peopledn}`;
		await this.#client.del(userDN, logger);
		const groups = await this.#client.search(this.#groupsdn, {
			scope: "one",
			filter: `(member=uid=${uid},${this.#peopledn})`
		}, logger);
		if (!logger.ok) {
			return logger;
		}
		for (const element of groups.entries) {
			const change = {
				operation: "delete",
				modification: {
					type: "member",
					values: [`uid=${uid},${this.#peopledn}`]
				}
			};
			await this.#client.modify(element.dn, change, logger);
		}
		return logger;
	}

	async getAllGroups () {
		const result = await this.#client.search(this.#groupsdn, {
			scope: "one"
		});
		result.groups = result.entries;
		return result;
	}

	async addGroup (gid) {
		const groupDN = `cn=${gid},${this.#groupsdn}`;
		const entry = {
			objectClass: "groupOfNames",
			member: "",
			cn: gid
		};
		return await this.#client.add(groupDN, entry);
	}

	async getGroup (gid) {
		const result = await this.#client.search(`cn=${gid},${this.#groupsdn}`, {});
		result.group = result.entries[0]; // assume there should only be 1 entry
		return result;
	}

	async delGroup (gid) {
		const groupDN = `cn=${gid},${this.#groupsdn}`;
		return await this.#client.del(groupDN);
	}

	async addUserToGroup (uid, gid) {
		// add the user
		const change = new ldap.Change({
			operation: "add",
			modification: {
				type: "member",
				values: [`uid=${uid},${this.#peopledn}`]
			}
		});
		return await this.#client.modify(`cn=${gid},${this.#groupsdn}`, change);
	}

	async delUserFromGroup (uid, gid) {
		const change = new ldap.Change({
			operation: "delete",
			modification: {
				type: "member",
				values: [`uid=${uid},${this.#peopledn}`]
			}
		});
		return await this.#client.modify(`cn=${gid},${this.#groupsdn}`, change);
	}
}

class LDAP_MULTIOP_LOGGER {
	op = null;
	ok = true;
	error = [];
	subops = [];
	constructor (op) {
		this.op = op;
	}

	push (op) {
		if (!op.ok) {
			this.ok = false;
			this.error.push(op.error);
		}
		this.subops.push(op);
	}
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

	#parseError (err) {
		if (err) {
			return { code: err.code, name: err.name, message: err.message };
		}
		else {
			return null;
		}
	}

	bind (dn, password, logger = null) {
		return new Promise((resolve) => {
			this.#client.bind(dn, password, (err) => {
				const result = { op: `bind ${dn}`, ok: err === null, error: this.#parseError(err) };
				if (logger) {
					logger.push(result);
				}
				resolve(result);
			});
		});
	}

	add (dn, entry, logger = null) {
		return new Promise((resolve) => {
			this.#client.add(dn, entry, (err) => {
				const result = { op: `add ${dn}`, ok: err === null, error: this.#parseError(err) };
				if (logger) {
					logger.push(result);
				}
				resolve(result);
			});
		});
	}

	search (base, options, logger = null) {
		return new Promise((resolve) => {
			this.#client.search(base, options, (err, res) => {
				if (err) {
					return resolve({ op: `search ${base}`, ok: false, error: err });
				}
				const result = { op: `search ${base}`, ok: false, error: null, entries: [] };
				res.on("searchRequest", (searchRequest) => { });
				res.on("searchEntry", (entry) => {
					const attributes = {};
					for (const element of entry.pojo.attributes) {
						attributes[element.type] = element.values;
					}
					result.entries.push({ dn: entry.pojo.objectName, attributes });
				});
				res.on("searchReference", (referral) => { });
				res.on("error", (err) => {
					result.ok = false;
					result.error = this.#parseError(err);
					if (logger) {
						logger.push(result);
					}
					resolve(result);
				});
				res.on("end", (res) => {
					result.ok = true;
					result.error = null;
					if (logger) {
						logger.push(result);
					}
					resolve(result);
				});
			});
		});
	}

	modify (name, changes, logger = null) {
		return new Promise((resolve) => {
			this.#client.modify(name, changes, (err) => {
				const result = { op: `modify ${name} ${changes.operation} ${changes.modification.type}`, ok: err === null, error: this.#parseError(err) };
				if (logger) {
					logger.push(result);
				}
				resolve(result);
			});
		});
	}

	del (dn, logger = null) {
		return new Promise((resolve) => {
			this.#client.del(dn, (err) => {
				const result = { op: `del ${dn}`, ok: err === null, error: this.#parseError(err) };
				if (logger) {
					logger.push(result);
				}
				resolve(result);
			});
		});
	}
}
