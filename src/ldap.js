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
		const logger = new LDAP_MULTIOP_LOGGER(`add ${uid}`);
		await this.#client.bind(bind.dn, bind.password, logger);
		if (!logger.ok) {
			return logger;
		}
		const userDN = `uid=${uid},${this.#peopledn}`;
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
		return await this.#client.search(`uid=${uid},${this.#peopledn}`, {});
	}

	async modUser (bind, uid, newAttrs) {
		const logger = new LDAP_MULTIOP_LOGGER(`modify ${uid}`);
		await this.#client.bind(bind.dn, bind.password, logger);
		if (!logger.ok) {
			return logger;
		}
		for (const attr of ["cn", "sn", "userPassword"]) {
			if (attr in newAttrs) {
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
		await this.#client.bind(bind.dn, bind.password, logger);
		if (!logger.ok) {
			return logger;
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
			let change = null;
			if (element.attributes.member.length === 1) {
				change = new ldap.Change({
					operation: "replace",
					modification: {
						type: "member",
						values: [""]
					}
				});
			}
			else {
				change = new ldap.Change({
					operation: "delete",
					modification: {
						type: "member",
						values: [`uid=${uid},${this.#peopledn}`]
					}
				});
			}
			await this.#client.modify(element.dn, change, logger);
		}
		return logger;
	}

	async addGroup (bind, gid, attrs) {
		const logger = new LDAP_MULTIOP_LOGGER(`add ${gid}`);
		await this.#client.bind(bind.dn, bind.password, logger);
		if (!logger.ok) {
			return logger;
		}
		const groupDN = `cn=${gid},${this.#groupsdn}`;
		const entry = {
			objectClass: "groupOfNames",
			member: attrs && attrs.member ? attrs.member : "",
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
		return await this.#client.search(`cn=${gid},${this.#groupsdn}`, {});
	}

	async delGroup (bind, gid) {
		const logger = new LDAP_MULTIOP_LOGGER(`del ${gid}`);
		await this.#client.bind(bind.dn, bind.password, logger);
		if (!logger.ok) {
			return logger;
		}
		const groupDN = `cn=${gid},${this.#groupsdn}`;
		await this.#client.del(groupDN, logger);
		return logger;
	}

	async addUserToGroup (bind, uid, gid) {
		const logger = new LDAP_MULTIOP_LOGGER(`add ${uid} to ${gid}`);
		await this.#client.bind(bind.dn, bind.password, logger);
		if (!logger.ok) {
			return logger;
		}
		const checkGroupEntry = await this.#client.search(`cn=${gid},${this.#groupsdn}`, {}, logger);
		if (logger.ok) {
			// add the user
			const change = new ldap.Change({
				operation: "add",
				modification: {
					type: "member",
					values: [`uid=${uid},${this.#peopledn}`]
				}
			});
			await this.#client.modify(`cn=${gid},${this.#groupsdn}`, change, logger);
			if (!logger.ok) {
				return logger;
			}
			// check if there is a blank entry in the group
			const groupEntry = checkGroupEntry.entries[0];
			if (groupEntry.attributes.member.includes("")) {
				// delete the blank user
				const change = new ldap.Change({
					operation: "delete",
					modification: {
						type: "member",
						values: [""]
					}
				});
				await this.#client.modify(`cn=${gid},${this.#groupsdn}`, change, logger);
			}
			return logger;
		}
		else {
			return logger;
		}
	}

	async delUserFromGroup (bind, uid, gid) {
		const logger = new LDAP_MULTIOP_LOGGER(`del ${uid} from ${gid}`);
		await this.#client.bind(bind.dn, bind.password, logger);
		if (!logger.ok) {
			return logger;
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

	async search (branch, opts) {
		return await this.#client.search(`${branch},${this.#basedn}`, opts);
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
			return {code: err.code, name: err.name, message: err.message};
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
