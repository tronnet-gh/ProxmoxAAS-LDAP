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

/**
 * POST - create a new user or modify existing user attributes
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

app.post("/groups/:groupid", (req, res) => {});

app.get("/groups/:groupid", (req, res) => {});

app.delete("/groups/:groupid", (req, res) => {});

app.get("/groups/:groupid/members", (req, res) => {});

app.post("/groups/:groupid/members", (req, res) => {});
