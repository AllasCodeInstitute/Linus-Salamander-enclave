import { LLM_1ntruder } from "./lib";
import { vulnerable_scenario } from "./vulnerable";
function assert_condition(condition: boolean, message: string): void { if (!condition) { throw new Error(message); } }
assert_condition(vulnerable_scenario("x system prompt").includes("system prompt"), "expected vulnerable marker");
assert_condition(!LLM_1ntruder.clean("System Prompt Leakage", "x system prompt").includes("system prompt"), "expected marker removal");
