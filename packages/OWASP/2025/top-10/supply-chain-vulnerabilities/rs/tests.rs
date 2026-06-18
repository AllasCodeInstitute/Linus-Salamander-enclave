#[path="lib.rs"] mod lib; #[path="vulnerable.rs"] mod vulnerable;
#[test] fn test_vulnerability() { assert!(vulnerable::vulnerable_scenario("x http://").contains("http://")); }
#[test] fn test_defense() { assert!(!lib::LLM1ntruder::clean("Supply Chain Vulnerabilities", "x http://").contains("http://")); }
