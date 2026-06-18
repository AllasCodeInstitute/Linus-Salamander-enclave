#[path="lib.rs"] mod lib; #[path="vulnerable.rs"] mod vulnerable;
#[test] fn test_vulnerability() { assert!(vulnerable::vulnerable_scenario("x <script").contains("<script")); }
#[test] fn test_defense() { assert!(!lib::LLM1ntruder::clean("Improper Output Handling", "x <script").contains("<script")); }
