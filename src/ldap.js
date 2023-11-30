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
		const bindResult = await this.#client.bind(bind.dn, bind.password);
		if (!bindResult.ok) {
			return bindResult;
		}
		const userDN = `uid=${uid},${this.#peopledn}`;
		const entry = {
			objectClass: "inetOrgPerson",
			cn: attrs.cn,
			sn: attrs.sn,
			uid,
			userPassword: attrs.userPassword
		};
		const addResult = await this.#client.add(userDN, entry);
		return { op: `add ${uid}`, ok: addResult.ok, error: addResult.error };
	}

	async getUser (bind, uid) {
		const bindResult = await this.#client.bind(bind.dn, bind.password);
		if (!bindResult.ok) {
			return bindResult;
		}
		return await this.#client.search(`uid=${uid},${this.#peopledn}`, {});
	}

	async modUser (bind, uid, newAttrs) {
		const bindResult = await this.#client.bind(bind.dn, bind.password);
		if (!bindResult.ok) {
			return bindResult;
		}
		const subops = [bindResult];
		for (const attr of ["cn", "sn", "userPassword"]) {
			if (attr in newAttrs) {
				const change = new ldap.Change({
					operation: "replace",
					modification: {
						type: attr,
						values: [newAttrs[attr]]
					}
				});
				subops.push(await this.#client.modify(`uid=${uid},${this.#peopledn}`, change));
			}
		}
		return { op: `modify ${uid}`, ok: !subops.some((e) => !e.ok), error: subops.find((e) => !e.ok) || null, subops };
	}

	async delUser (bind, uid) {
		const bindResult = await this.#client.bind(bind.dn, bind.password);
		if (!bindResult.ok) {
			return bindResult;
		}
		const userDN = `uid=${uid},${this.#peopledn}`;
		const delResult = await this.#client.del(userDN);
		const groups = await this.#client.search(this.#groupsdn, {
			scope: "one",
			filter: `(member=uid=${uid},${this.#peopledn})`
		});
		if (!groups.ok) {
			return { op: `del ${uid}`, ok: groups.ok, error: groups.error, subops: [bindResult, delResult, groups]}
		}
		const groupsubops = [];
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
			const delResult = await this.#client.modify(element.dn, change);
			groupsubops.push(delResult);
		}
		return { op: `del ${uid}`, ok: delResult.ok, error: delResult.error, subops: [bindResult, delResult, groups].concat(groupsubops) };
	}

	async addGroup (bind, gid, attrs) {
		const bindResult = await this.#client.bind(bind.dn, bind.password);
		if (!bindResult.ok) {
			return bindResult;
		}
		const groupDN = `cn=${gid},${this.#groupsdn}`;
		const entry = {
			objectClass: "groupOfNames",
			member: attrs && attrs.member ? attrs.member : "",
			cn: gid
		};
		const addResult = await this.#client.add(groupDN, entry);
		return { op: `add ${gid}`, ok: addResult.ok, error: addResult.error, subops: [bindResult, addResult] };
	}

	async getGroup (bind, gid) {
		const bindResult = await this.#client.bind(bind.dn, bind.password);
		if (!bindResult.ok) {
			return bindResult;
		}
		return await this.#client.search(`cn=${gid},${this.#groupsdn}`, {});
	}

	async delGroup (bind, gid) {
		const bindResult = await this.#client.bind(bind.dn, bind.password);
		if (!bindResult.ok) {
			return bindResult;
		}
		const groupDN = `cn=${gid},${this.#groupsdn}`;
		const delResult = await this.#client.del(groupDN);
		return { op: `del ${gid}`, ok: delResult.ok, error: delResult.error, subops: [bindResult, delResult] };
	}

	async addUserToGroup (bind, uid, gid) {
		const bindResult = await this.#client.bind(bind.dn, bind.password);
		if (!bindResult.ok) {
			return bindResult;
		}
		const checkGroupEntry = await this.#client.search(`cn=${gid},${this.#groupsdn}`, {});
		if (checkGroupEntry.ok) {
			// add the user
			const change = new ldap.Change({
				operation: "add",
				modification: {
					type: "member",
					values: [`uid=${uid},${this.#peopledn}`]
				}
			});
			const addResult = await this.#client.modify(`cn=${gid},${this.#groupsdn}`, change);
			if (!addResult.ok) {
				return addResult;
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
				const fixResult = await this.#client.modify(`cn=${gid},${this.#groupsdn}`, change);
				return { op: `add ${uid} to ${gid}`, ok: addResult.ok && fixResult.ok, error: addResult.error ? addResult.error : fixResult.error, subops: [bindResult, addResult, fixResult] };
			}
			return { op: `add ${uid} to ${gid}`, ok: true, error: null, subops: [bindResult, addResult] };
		}
		else {
			return { op: `add ${uid} to ${gid}`, ok: false, error: `${gid} does not exist`, subops: [bindResult] };
		}
	}

	async delUserFromGroup (bind, uid, gid) {
		const bindResult = await this.#client.bind(bind.dn, bind.password);
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
		const delResult = await this.#client.modify(`cn=${gid},${this.#groupsdn}`, change);
		return { op: `del ${uid} from ${gid}`, ok: delResult.ok, error: delResult.error, subops: [bindResult, delResult] };
	}

	async search (base, opts) {
		return await this.#client.search(base, opts);
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

	bind (dn, password) {
		return new Promise((resolve) => {
			this.#client.bind(dn, password, (err) => {
				if (err) {
					resolve({ op: `bind ${dn}`, ok: false, error: err });
				}
				else {
					resolve({ op: `bind ${dn}`, ok: true, error: null });
				}
			});
		});
	}

	add (dn, entry) {
		return new Promise((resolve) => {
			this.#client.add(dn, entry, (err) => {
				if (err) {
					resolve({ op: `add ${dn}`, ok: false, error: err });
				}
				else {
					resolve({ op: `add ${dn}`, ok: true, error: null });
				}
			});
		});
	}

	search (base, options) {
		return new Promise((resolve) => {
			this.#client.search(base, options, (err, res) => {
				if (err) {
					return resolve({ op: `search ${base}`, ok: false, error: err });
				}
				const results = { op: `search ${base}`, ok: false, error: null, status: 1, message: "", entries: [] };
				res.on("searchRequest", (searchRequest) => { });
				res.on("searchEntry", (entry) => {
					const attributes = {};
					for (const element of entry.pojo.attributes) {
						attributes[element.type] = element.values;
					}
					results.entries.push({ dn: entry.pojo.objectName, attributes });
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
					resolve({ op: `modify ${name} ${changes.operation} ${changes.modification.type}`, ok: false, error: err });
				}
				else {
					resolve({ op: `modify ${name} ${changes.operation} ${changes.modification.type}`, ok: true, error: null });
				}
			});
		});
	}

	del (dn) {
		return new Promise((resolve) => {
			this.#client.del(dn, (err) => {
				if (err) {
					resolve({ op: `del ${dn}`, ok: false, error: err });
				}
				else {
					resolve({ op: `del ${dn}`, ok: true, error: null });
				}
			});
		});
	}
}
