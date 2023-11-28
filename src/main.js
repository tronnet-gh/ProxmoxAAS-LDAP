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
