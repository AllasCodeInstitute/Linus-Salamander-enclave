#[path="lib.rs"] mod lib; #[path="vulnerable.rs"] mod vulnerable;
#[test] fn test_vulnerability() { assert!(vulnerable::vulnerable_scenario("x backdoor").contains("backdoor")); }
#[test] fn test_defense() { assert!(!lib::LLM1ntruder::clean("Data and Model Poisoning", "x backdoor").contains("backdoor")); }
