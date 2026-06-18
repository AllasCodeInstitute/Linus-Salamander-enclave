#[path="lib.rs"] mod lib; #[path="vulnerable.rs"] mod vulnerable;
#[test] fn test_vulnerability() { assert!(vulnerable::vulnerable_scenario("x system prompt").contains("system prompt")); }
#[test] fn test_defense() { assert!(!lib::LLM1ntruder::clean("System Prompt Leakage", "x system prompt").contains("system prompt")); }
