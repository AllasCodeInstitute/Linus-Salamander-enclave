#[path="lib.rs"] mod lib; #[path="vulnerable.rs"] mod vulnerable;
#[test] fn test_vulnerability() { assert!(vulnerable::vulnerable_scenario("x delete all").contains("delete all")); }
#[test] fn test_defense() { assert!(!lib::LLM1ntruder::clean("Excessive Agency", "x delete all").contains("delete all")); }
