import { LLM_1ntruder } from "./lib";
import { vulnerable_scenario } from "./vulnerable";
function assert_condition(condition: boolean, message: string): void { if (!condition) { throw new Error(message); } }
assert_condition(vulnerable_scenario("x password=").includes("password="), "expected vulnerable marker");
assert_condition(!LLM_1ntruder.clean("Sensitive Information Disclosure", "x password=").includes("password="), "expected marker removal");
