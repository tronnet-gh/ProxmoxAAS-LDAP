import { readFileSync } from "fs";
import { exit } from "process";

export function readJSONFile (path) {
	try {
		return JSON.parse(readFileSync(path));
	}
	catch (e) {
		console.log(`error: ${path} was not found.`);
		exit(1);
	}
};
