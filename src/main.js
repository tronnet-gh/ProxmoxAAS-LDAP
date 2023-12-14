import express from "express";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import cors from "cors";
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
app.use(cors({ origin: global.db.hostname }));
app.use(morgan("combined"));

// endpoint handles both adding a new user and updating an existing user including password and groups
app.post("/users/:userid", (req, res) => {});

app.get("/users/:userid", (req, res) => {});

app.delete("/users/:userid", (req, res) => {});

app.post("/groups/:groupid", (req, res) => {});

app.get("/groups/:groupid", (req, res) => {});

app.delete("/groups/:groupid", (req, res) => {});