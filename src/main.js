import express from "express";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import morgan from "morgan";
import session from "express-session";
import parseArgs from "minimist";

import * as utils from "./utils.js";
import LDAP from "./ldap.js";

global.argv = parseArgs(process.argv.slice(2), {
	default: {
		package: "package.json",
		config: "config/config.json"
	}
});

global.utils = utils;
global.package = global.utils.readJSONFile(global.argv.package);
global.config = global.utils.readJSONFile(global.argv.config);

const LDAPSessions = {};

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(morgan("combined"));
app.use(session({
	secret: global.config.sessionSecretKey,
	name: global.config.sessionCookieName,
	cookie: global.config.sessionCookie,
	resave: false,
	saveUninitialized: true
}));

app.listen(global.config.listenPort, () => {
	console.log(`proxmoxaas-ldap v${global.package.version} listening on port ${global.config.listenPort}`);
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

/**
 * POST - get session ticket by authenticating using user id and password
 */
app.post("/ticket", async (req, res) => {
	const params = {
		uid: req.body.uid,
		password: req.body.password
	};
	const newLDAPSession = new LDAP(global.config.ldapURL, global.config.basedn);
	const bindResult = await newLDAPSession.bindUser(params.uid, params.password);
	if (bindResult.ok) {
		LDAPSessions[req.session.id] = newLDAPSession;
		res.status(200).send({ auth: true });
	}
	else {
		res.status(403).send({
			ok: bindResult.ok,
			error: bindResult.error
		});
	}
});

/**
 * DELETE - invalidate and remove session ticket
 */
app.delete("/ticket", async (req, res) => {
	req.session.ldap = null;
	req.session.destroy();
	res.send({ auth: false });
});

/**
 * GET - get user attributes for all users
 */
app.get("/users", async (req, res) => {
	if (req.session.id in LDAPSessions) {
		const ldap = LDAPSessions[req.session.id];
		const result = await ldap.getAllUsers();
		res.send({
			ok: result.ok,
			error: result.error,
			users: result.users
		});
	}
	else {
		res.status(403).send({ auth: false });
	}
});

/**
 * POST - create a new user or modify existing user attributes
 * request:
 * - userid: user id
 * - cn: common name
 * - sn: surname
 * - userpassword: user password
 */
app.post("/users/:userid", async (req, res) => {
	const params = {
		userid: req.params.userid,
		userattrs: {
			cn: req.body.usercn,
			sn: req.body.usersn,
			userPassword: req.body.userpassword
		}
	};
	if (req.session.id in LDAPSessions) {
		const ldap = LDAPSessions[req.session.id];
		const checkUser = await ldap.getUser(params.userid);
		if (!checkUser.ok && checkUser.error.code === 32) { // the user does not exist, create new user
			const result = await ldap.addUser(params.userid, params.userattrs);
			res.send({
				ok: result.ok,
				error: result.error
			});
		}
		else if (checkUser.ok) { // the user does exist, modify the user entries
			const result = await ldap.modUser(params.userid, params.userattrs);
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
	}
	else {
		res.status(403).send({ auth: false });
	}
});

/**
 * GET - get user attributes
 * request:
 * - userid: user id
 */
app.get("/users/:userid", async (req, res) => {
	const params = {
		userid: req.params.userid
	};
	if (req.session.id in LDAPSessions) {
		const ldap = LDAPSessions[req.session.id];
		const result = await ldap.getUser(params.userid);
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
	}
	else {
		res.status(403).send({ auth: false });
	}
});

/**
 * DELETE - delete user
 * request:
 * - userid: user id
 */
app.delete("/users/:userid", async (req, res) => {
	const params = {
		userid: req.params.userid
	};
	if (req.session.id in LDAPSessions) {
		const ldap = LDAPSessions[req.session.id];
		const result = await ldap.delUser(params.userid);
		res.send({
			ok: result.ok,
			error: result.error
		});
	}
	else {
		res.status(403).send({ auth: false });
	}
});

/**
 * GET - get group attributes including members for all groups
 * request:
 */
app.get("/groups", async (req, res) => {
	if (req.session.id in LDAPSessions) {
		const ldap = LDAPSessions[req.session.id];
		const result = await ldap.getAllGroups();
		res.send({
			ok: result.ok,
			error: result.error,
			groups: result.groups
		});
	}
	else {
		res.status(403).send({ auth: false });
	}
});

/**
 * POST - create a new group
 * request:
 * - groupid: group id
 */
app.post("/groups/:groupid", async (req, res) => {
	const params = {
		groupid: req.params.groupid
	};
	if (req.session.id in LDAPSessions) {
		const ldap = LDAPSessions[req.session.id];
		const result = await ldap.addGroup(params.groupid);
		res.send({
			ok: result.ok,
			error: result.error
		});
	}
	else {
		res.status(403).send({ auth: false });
	}
});

/**
 * GET - get group attributes including members
 * request:
 * - groupid: group id
 */
app.get("/groups/:groupid", async (req, res) => {
	const params = {
		groupid: req.params.groupid
	};
	if (req.session.id in LDAPSessions) {
		const ldap = LDAPSessions[req.session.id];
		const result = await ldap.getGroup(params.groupid);
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
	}
	else {
		res.status(403).send({ auth: false });
	}
});

/**
 * DELETE - delete group
 * request:
 * - groupid: group id
 */
app.delete("/groups/:groupid", async (req, res) => {
	const params = {
		groupid: req.params.groupid
	};
	if (req.session.id in LDAPSessions) {
		const ldap = LDAPSessions[req.session.id];
		const result = await ldap.delGroup(params.groupid);
		res.send({
			ok: result.ok,
			error: result.error
		});
	}
	else {
		res.status(403).send({ auth: false });
	}
});

/**
 * POST - add a member to the group
 * request:
 * - groupid: group id
 * - userid: user id
 */
app.post("/groups/:groupid/members/:userid", async (req, res) => {
	const params = {
		groupid: req.params.groupid,
		userid: req.params.userid
	};
	if (req.session.id in LDAPSessions) {
		const ldap = LDAPSessions[req.session.id];
		const result = await ldap.addUserToGroup(params.userid, params.groupid);
		res.send({
			ok: result.ok,
			error: result.error
		});
	}
	else {
		res.status(403).send({ auth: false });
	}
});

/**
 * DELETE - remove a member from the group
 * - groupid: group id
 * - userid: user id
 */
app.delete("/groups/:groupid/members/:userid", async (req, res) => {
	const params = {
		groupid: req.params.groupid,
		userid: req.params.userid
	};
	if (req.session.id in LDAPSessions) {
		const ldap = LDAPSessions[req.session.id];
		const result = await ldap.delUserFromGroup(params.userid, params.groupid);
		res.send({
			ok: result.ok,
			error: result.error
		});
	}
	else {
		res.status(403).send({ auth: false });
	}
});
