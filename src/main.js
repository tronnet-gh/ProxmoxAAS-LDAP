import express from "express";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import morgan from "morgan";
import LDAP from "ldap.js";

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(morgan("combined"));

app.listen(global.db.listenPort, () => {
	console.log(`proxmoxaas-api v${global.api.version} listening on port ${global.db.listenPort}`);
});

app.get("/:user", (req, res) => {

});

app.post("/:user", (req, res) => {

});

app.delete("/:user", (req, res) => {

});

app.post("/:user/password", (req, res) => {

});
