#[path="lib.rs"] mod lib; #[path="vulnerable.rs"] mod vulnerable;
#[test] fn test_vulnerability() { assert!(vulnerable::vulnerable_scenario("x password=").contains("password=")); }
#[test] fn test_defense() { assert!(!lib::LLM1ntruder::clean("Sensitive Information Disclosure", "x password=").contains("password=")); }
