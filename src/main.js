import express from "express";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import morgan from "morgan";

import LDAP from "./ldap.js";
import _config from "./config.js";
import _package from "./package.js";

import parseArgs from "minimist";

global.argv = parseArgs(process.argv.slice(2), {
	default: {
		package: "package.json",
		listenPort: 8082,
		ldapURL: "ldap://localhost",
		configPath: "config/config.json"
	}
});

global.package = _package(global.argv.package);
global.config = _config(global.argv.configPath);

const ldap = new LDAP(global.argv.ldapURL, global.config.basedn);

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(morgan("combined"));

app.listen(global.argv.listenPort, () => {
	console.log(`proxmoxaas-api v${global.package.version} listening on port ${global.argv.listenPort}`);
});

/**
 * GET - get API version
 * responses:
 * - 200: {version: string}
 */
app.get("/version", (req, res) => {
	res.status(200).send({ version: global.package.version });
});

/**
 * GET - echo request
 * responses:
 * - 200: {body: request.body, cookies: request.cookies}
 */
app.get("/echo", (req, res) => {
	res.status(200).send({ body: req.body, cookies: req.cookies });
});

app.get("/users", async (req, res) => {
	const params = {
		bind: ldap.createUserBind(req.body.binduser, req.body.bindpass)
	};
	const result = await ldap.getAllUsers(params.bind);
	res.send({
		ok: result.ok,
		error: result.error,
		users: result.users
	});
});

/**
 * POST - create a new user or modify existing user attributes
 * request:
 * - userid: user id
 * - cn: common name
 * - sn: surname
 * - userpassword: user password
 * - binduser: bind user id
 * - bindpass: bind user password
 */
app.post("/users/:userid", async (req, res) => {
	const params = {
		userid: req.params.userid,
		bind: ldap.createUserBind(req.body.binduser, req.body.bindpass),
		userattrs: {
			cn: req.body.usercn,
			sn: req.body.usersn,
			userPassword: req.body.userpassword
		}
	};
	const checkUser = await ldap.getUser(params.bind, params.userid);
	if (!checkUser.ok && checkUser.error.code === 32) { // the user does not exist, create new user
		const result = await ldap.addUser(params.bind, params.userid, params.userattrs);
		res.send({
			ok: result.ok,
			error: result.error
		});
	}
	else if (checkUser.ok) { // the user does exist, modify the user entries
		const result = await ldap.modUser(params.bind, params.userid, params.userattrs);
		res.send({
			ok: result.ok,
			error: result.error
		});
	}
	else { // some other error happened
		res.send({
			ok: checkUser.ok,
			error: checkUser.error
		});
	}
});

/**
 * GET - get user attributes
 * request:
 * - userid: user id
 * - binduser: bind user id
 * - bindpass: bind user password
 */
app.get("/users/:userid", async (req, res) => {
	const params = {
		userid: req.params.userid,
		bind: ldap.createUserBind(req.body.binduser, req.body.bindpass)
	};
	const result = await ldap.getUser(params.bind, params.userid);
	if (result.ok) {
		res.send({
			ok: result.ok,
			error: result.error,
			user: result.user
		});
	}
	else {
		res.send({
			ok: result.ok,
			error: result.error
		});
	}
});

/**
 * DELETE - delete user
 * request:
 * - userid: user id
 * - binduser: bind user id
 * - bindpass: bind user password
 */
app.delete("/users/:userid", async (req, res) => {
	const params = {
		userid: req.params.userid,
		bind: ldap.createUserBind(req.body.binduser, req.body.bindpass)
	};
	const result = await ldap.delUser(params.bind, params.userid);
	res.send({
		ok: result.ok,
		error: result.error
	});
});

app.get("/groups", async (req, res) => {
	const params = {
		bind: ldap.createUserBind(req.body.binduser, req.body.bindpass)
	};
	const result = await ldap.getAllGroups(params.bind);
	res.send({
		ok: result.ok,
		error: result.error,
		groups: result.groups
	});
});

/**
 * POST - create a new group
 * request:
 * - groupid: group id
 * - binduser: bind user id
 * - bindpass: bind user password
 */
app.post("/groups/:groupid", async (req, res) => {
	const params = {
		groupid: req.params.groupid,
		bind: ldap.createUserBind(req.body.binduser, req.body.bindpass)
	};
	const result = await ldap.addGroup(params.bind, params.groupid);
	res.send({
		ok: result.ok,
		error: result.error
	});
});

/**
 * GET - get group attributes including members
 * request:
 * - groupid: group id
 * - binduser: bind user id
 * - bindpass: bind user password
 */
app.get("/groups/:groupid", async (req, res) => {
	const params = {
		groupid: req.params.groupid,
		bind: ldap.createUserBind(req.body.binduser, req.body.bindpass)
	};
	const result = await ldap.getGroup(params.bind, params.groupid);
	if (result.ok) {
		res.send({
			ok: result.ok,
			error: result.error,
			group: result.group
		});
	}
	else {
		res.send({
			ok: result.ok,
			error: result.error
		});
	}
});

/**
 * DELETE - delete group
 * request:
 * - groupid: group id
 * - binduser: bind user id
 * - bindpass: bind user password
 */
app.delete("/groups/:groupid", async (req, res) => {
	const params = {
		groupid: req.params.groupid,
		bind: ldap.createUserBind(req.body.binduser, req.body.bindpass)
	};
	const result = await ldap.delGroup(params.bind, params.groupid);
	res.send({
		ok: result.ok,
		error: result.error
	});
});

/**
 * POST - add a member to the group
 * request:
 * - groupid: group id
 * - userid: user id
 * - binduser: bind user id
 * - bindpass: bind user password
 */
app.post("/groups/:groupid/members/:userid", async (req, res) => {
	const params = {
		groupid: req.params.groupid,
		userid: req.params.userid,
		bind: ldap.createUserBind(req.body.binduser, req.body.bindpass)
	};
	const result = await ldap.addUserToGroup(params.bind, params.userid, params.groupid);
	res.send({
		ok: result.ok,
		error: result.error
	});
});

/**
 * DELETE - remove a member from the group
 * - groupid: group id
 * - userid: user id
 * - binduser: bind user id
 * - bindpass: bind user password
 */
app.delete("/groups/:groupid/members/:userid", async (req, res) => {
	const params = {
		groupid: req.params.groupid,
		userid: req.params.userid,
		bind: ldap.createUserBind(req.body.binduser, req.body.bindpass)
	};
	const result = await ldap.delUserFromGroup(params.bind, params.userid, params.groupid);
	res.send({
		ok: result.ok,
		error: result.error
	});
});
