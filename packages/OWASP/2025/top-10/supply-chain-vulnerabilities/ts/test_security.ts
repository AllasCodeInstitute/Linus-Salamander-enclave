import { LLM_1ntruder } from "./lib";
import { vulnerable_scenario } from "./vulnerable";
function assert_condition(condition: boolean, message: string): void { if (!condition) { throw new Error(message); } }
assert_condition(vulnerable_scenario("x http://").includes("http://"), "expected vulnerable marker");
assert_condition(!LLM_1ntruder.clean("Supply Chain Vulnerabilities", "x http://").includes("http://"), "expected marker removal");
