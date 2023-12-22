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

	createUserBind (uid, password) {
		return {
			dn: `uid=${uid},${this.#peopledn}`,
			password
		};
	}

	async getAllUsers (bind) {
		const bindResult = await this.#client.bind(bind.dn, bind.password);
		if (!bindResult.ok) {
			return bindResult;
		}
		const result = await this.#client.search(this.#peopledn, {
			scope: "one"
		});
		result.users = result.entries;
		return result;
	}

	async addUser (bind, uid, attrs) {
		const logger = new LDAP_MULTIOP_LOGGER(`add ${uid}`);
		const bindResult = await this.#client.bind(bind.dn, bind.password, logger);
		if (!bindResult.ok) {
			return bindResult;
		}
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
		await this.#client.add(userDN, entry, logger);
		return logger;
	}

	async getUser (bind, uid) {
		const bindResult = await this.#client.bind(bind.dn, bind.password);
		if (!bindResult.ok) {
			return bindResult;
		}
		const result = await this.#client.search(`uid=${uid},${this.#peopledn}`, {});
		result.user = result.entries[0]; // assume there should only be 1 entry
		return result;
	}

	async modUser (bind, uid, newAttrs) {
		const logger = new LDAP_MULTIOP_LOGGER(`modify ${uid}`);
		const bindResult = await this.#client.bind(bind.dn, bind.password, logger);
		if (!bindResult.ok) {
			return bindResult;
		}
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

	async delUser (bind, uid) {
		const logger = new LDAP_MULTIOP_LOGGER(`del ${uid}`);
		const bindResult = await this.#client.bind(bind.dn, bind.password, logger);
		if (!bindResult.ok) {
			return bindResult;
		}
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

	async getAllGroups (bind) {
		const bindResult = await this.#client.bind(bind.dn, bind.password);
		if (!bindResult.ok) {
			return bindResult;
		}
		const result = await this.#client.search(this.#groupsdn, {
			scope: "one"
		});
		result.groups = result.entries;
		return result;
	}

	async addGroup (bind, gid) {
		const logger = new LDAP_MULTIOP_LOGGER(`add ${gid}`);
		const bindResult = await this.#client.bind(bind.dn, bind.password, logger);
		if (!bindResult.ok) {
			return bindResult;
		}
		const groupDN = `cn=${gid},${this.#groupsdn}`;
		const entry = {
			objectClass: "groupOfNames",
			member: "",
			cn: gid
		};
		await this.#client.add(groupDN, entry, logger);
		return logger;
	}

	async getGroup (bind, gid) {
		const bindResult = await this.#client.bind(bind.dn, bind.password);
		if (!bindResult.ok) {
			return bindResult;
		}
		const result = await this.#client.search(`cn=${gid},${this.#groupsdn}`, {});
		result.group = result.entries[0]; // assume there should only be 1 entry
		return result;
	}

	async delGroup (bind, gid) {
		const logger = new LDAP_MULTIOP_LOGGER(`del ${gid}`);
		const bindResult = await this.#client.bind(bind.dn, bind.password, logger);
		if (!bindResult.ok) {
			return bindResult;
		}
		const groupDN = `cn=${gid},${this.#groupsdn}`;
		await this.#client.del(groupDN, logger);
		return logger;
	}

	async addUserToGroup (bind, uid, gid) {
		const logger = new LDAP_MULTIOP_LOGGER(`add ${uid} to ${gid}`);
		const bindResult = await this.#client.bind(bind.dn, bind.password, logger);
		if (!bindResult.ok) {
			return bindResult;
		}
		// add the user
		const change = new ldap.Change({
			operation: "add",
			modification: {
				type: "member",
				values: [`uid=${uid},${this.#peopledn}`]
			}
		});
		await this.#client.modify(`cn=${gid},${this.#groupsdn}`, change, logger);
		return logger;
	}

	async delUserFromGroup (bind, uid, gid) {
		const logger = new LDAP_MULTIOP_LOGGER(`del ${uid} from ${gid}`);
		const bindResult = await this.#client.bind(bind.dn, bind.password, logger);
		if (!bindResult.ok) {
			return bindResult;
		}
		const change = new ldap.Change({
			operation: "delete",
			modification: {
				type: "member",
				values: [`uid=${uid},${this.#peopledn}`]
			}
		});
		await this.#client.modify(`cn=${gid},${this.#groupsdn}`, change, logger);
		return logger;
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
