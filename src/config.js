import { readFileSync } from "fs";
import { exit } from "process";
export default () => {
	try {
		return JSON.parse(readFileSync(global.argv.configPath));
	}
	catch (e) {
		console.log(`Error: ${global.argv.configPath} was not found. Please follow the directions in the README to initialize localdb.json.`);
		exit(1);
	}
};
