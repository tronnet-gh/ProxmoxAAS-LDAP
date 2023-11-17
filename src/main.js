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

/* import { readFileSync } from "fs";
const paas = {
	dn: `uid=paas,ou=people,${global.config.basedn}`,
	password: readFileSync("paas.token").toString()
};
console.log(await ldap.addUser(paas, "testuser", { cn: "test", sn: "test", userPassword: "test" }));
console.log((await ldap.getUser(paas, "testuser")).entries[0].attributes);
console.log(await ldap.delUser(paas, "testuser"));
console.log(await ldap.addGroup(paas, "testgroup"));
console.log(await ldap.delGroup(paas, "testgroup"));
exit(0); */

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(morgan("combined"));

app.listen(global.argv.listenPort, () => {
	console.log(`proxmoxaas-ldap v${global.package.version} listening on port ${global.argv.listenPort}`);
});

app.get("/:user", async (req, res) => {
});

app.post("/:user", async (req, res) => {
});

app.delete("/:user", async (req, res) => {
});

app.post("/:user/password", async (req, res) => {
});
