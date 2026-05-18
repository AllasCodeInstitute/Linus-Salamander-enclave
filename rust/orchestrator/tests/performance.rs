// Performance, Load and Stress Testing for Vault Core
use std::time::{Instant, Duration};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};

#[repr(C)]
pub struct AgentPacket {
    pub payload_ptr: *mut u8,
    pub len: usize,
    pub session_id: u64,
}

extern "C" {
    fn init_enclave_keys();
    fn noise_sign_payload(payload_ptr: *const u8, len: usize, out_sig: *mut u8) -> i32;
}

#[test]
fn test_performance_throughput_stress() {
    unsafe { init_enclave_keys() };
    
    let mock_payload = vec![0u8; 1024]; // 1KB payload
    let mut signature = [0u8; 64];
    
    let iterations = 1_000;
    let start = Instant::now();
    
    for i in 0..iterations {
        let status = unsafe { 
            noise_sign_payload(mock_payload.as_ptr(), mock_payload.len(), signature.as_mut_ptr()) 
        };
        if status != 0 { panic!("Failed at iteration {}", i); }
    }
    
    let duration = start.elapsed();
    let tps = iterations as f64 / duration.as_secs_f64();
    let latency = duration / iterations as u32;

    println!("\n🚀 PERFORMANCE RESULTS");
    println!("---------------------");
    println!("Total Iterations: {}", iterations);
    println!("Total Time: {:?}", duration);
    println!("Throughput: {:.2} Signatures/sec", tps);
    println!("Avg Latency: {:?}", latency);
    
    assert!(tps > 10_000.0, "Throughput should be at least 10k ops/sec on modern hardware");
}

#[test]
fn test_stress_concurrency_simulation() {
    // Stress test usually involves hammering the system.
    // Since our Enclave uses a global static mut (simulated), 
    // we test serial stress in a tight loop.
    
    let iterations = 5_000;
    unsafe { init_enclave_keys() };
    
    let mut signature = [0u8; 64];
    let payload = b"stress-test-data";

    for _ in 0..iterations {
        unsafe {
            noise_sign_payload(payload.as_ptr(), payload.len(), signature.as_mut_ptr());
        }
    }
    
    println!("✅ Stress test completed: {} signatures processed.", iterations);
}
