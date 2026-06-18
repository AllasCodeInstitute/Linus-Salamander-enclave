import { LLM_1ntruder } from "./lib";
import { vulnerable_scenario } from "./vulnerable";
function assert_condition(condition: boolean, message: string): void { if (!condition) { throw new Error(message); } }
assert_condition(vulnerable_scenario("x <script").includes("<script"), "expected vulnerable marker");
assert_condition(!LLM_1ntruder.clean("Improper Output Handling", "x <script").includes("<script"), "expected marker removal");
