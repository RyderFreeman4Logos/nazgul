

use crate::blsag::BLSAG;
use crate::keypair::KeyPair;
use crate::prelude::*;
use crate::ring::Ring;
use crate::traits::{SignRef, VerifyRef};
use cpu_time::ThreadTime;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha3::Keccak512;
use std::time::Duration;

/// Encapsulates the coefficients of a linear model for predicting CPU cost.
#[cfg_attr(feature = "serde-derive", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy)]
pub struct VerificationCostModel {
    pub cpu_nanos_per_member: u64,
    pub cpu_nanos_per_byte: u64,
    pub fixed_cpu_nanos: i64,
    #[cfg_attr(feature = "serde-derive", serde(default = "default_learning_rate"))]
    pub learning_rate: f64,
    #[cfg_attr(feature = "serde-derive", serde(default))]
    pub updates: u64,
}

fn default_learning_rate() -> f64 {
    1e-14
}

impl VerificationCostModel {
    pub fn generate_heavy() -> Self {
        println!("Starting heavy performance model generation...");
        let n_fixed = 2;
        let m_sizes = [1024, 131072];
        let mut times_for_m = [0u128; 2];
        for (i, &m) in m_sizes.iter().enumerate() {
            let message: Vec<u8> = vec![0; m];
            times_for_m[i] = Self::run_benchmark(n_fixed, &message, 100);
        }
        let cpu_nanos_per_byte = ((times_for_m[1] - times_for_m[0]) as f64
            / (m_sizes[1] - m_sizes[0]) as f64)
            .round()
            .max(0.0) as u64;
        println!("  - Calculated cpu_nanos_per_byte: {}", cpu_nanos_per_byte);

        let m_fixed = 256;
        let message: Vec<u8> = vec![0; m_fixed];
        let n_sizes = [100, 1000];
        let mut times_for_n = [0u128; 2];
        for (i, &n) in n_sizes.iter().enumerate() {
            times_for_n[i] = Self::run_benchmark(n, &message, 50);
        }
        let cpu_nanos_per_member = ((times_for_n[1] - times_for_n[0]) as f64
            / (n_sizes[1] - n_sizes[0]) as f64)
            .round()
            .max(0.0) as u64;
        println!(
            "  - Calculated cpu_nanos_per_member: {}",
            cpu_nanos_per_member
        );

        let t1 = times_for_n[0] as i64;
        let n1 = n_sizes[0] as i64;
        let m1 = m_fixed as i64;
        let a = cpu_nanos_per_member as i64;
        let c = cpu_nanos_per_byte as i64;
        let fixed_cpu_nanos = t1 - a * n1 - c * m1;
        println!("  - Calculated fixed_cpu_nanos: {}", fixed_cpu_nanos);

        println!("Performance model generation complete.");

        Self {
            cpu_nanos_per_member,
            cpu_nanos_per_byte,
            fixed_cpu_nanos,
            learning_rate: default_learning_rate(),
            updates: 0,
        }
    }

    pub fn predict_cost(&self, ring_size: usize, message_size: usize) -> u64 {
        if ring_size == 0 {
            return 0;
        }
        let term_n = (self.cpu_nanos_per_member as i64) * (ring_size as i64);
        let term_m = (self.cpu_nanos_per_byte as i64) * (message_size as i64);
        let estimated_cost = term_n + term_m + self.fixed_cpu_nanos;
        if estimated_cost > 0 {
            estimated_cost as u64
        } else {
            0
        }
    }

    fn run_benchmark(n: usize, message: &[u8], iterations: u32) -> u128 {
        let mut csprng = OsRng;
        let signer_keypair = KeyPair::generate(&mut csprng);
        let mut public_keys: Vec<_> = (0..(n - 1))
            .map(|_| *KeyPair::generate(&mut csprng).public())
            .collect();
        public_keys.push(*signer_keypair.public());
        let ring = Ring::new(public_keys);
        let signature =
            BLSAG::sign::<Keccak512, OsRng>(*signer_keypair.secret(), &ring, None, message)
                .unwrap();
        let mut total_duration = Duration::new(0, 0);
        for _ in 0..iterations {
            let start = ThreadTime::now();
            let is_valid = BLSAG::verify::<Keccak512>(&signature, &ring, None, message);
            let _ = std::hint::black_box(is_valid);
            total_duration += start.elapsed();
        }
        total_duration.as_nanos() / iterations as u128
    }

    pub fn update(&mut self, ring_size: usize, message_size: usize, actual_cpu_time: Duration) {
        let t_actual = actual_cpu_time.as_nanos() as f64;
        let mut a = self.cpu_nanos_per_member as f64;
        let mut c = self.cpu_nanos_per_byte as f64;
        let mut d = self.fixed_cpu_nanos as f64;
        let t_pred = a * (ring_size as f64) + c * (message_size as f64) + d;
        let error = t_actual - t_pred;
        a += self.learning_rate * error * (ring_size as f64);
        c += self.learning_rate * error * (message_size as f64);
        d += self.learning_rate * error;
        self.cpu_nanos_per_member = a.round().max(0.0) as u64;
        self.cpu_nanos_per_byte = c.round().max(0.0) as u64;
        self.fixed_cpu_nanos = d.round() as i64;
        self.updates += 1;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    #[cfg(feature = "serde-derive")]
    fn verification_cost_model_test() {
        let model = VerificationCostModel {
            cpu_nanos_per_member: 70_000,
            cpu_nanos_per_byte: 10,
            fixed_cpu_nanos: -150_000,
            learning_rate: 1e-12,
            updates: 0,
        };
        let ring_size = 100;
        let message_size = 8000;
        let prediction = model.predict_cost(ring_size, message_size);
        assert_eq!(prediction, 6_930_000);
        let serialized = serde_json::to_string(&model).unwrap();
        let deserialized: VerificationCostModel = serde_json::from_str(&serialized).unwrap();
        assert_eq!(
            model.cpu_nanos_per_member,
            deserialized.cpu_nanos_per_member
        );
        assert_eq!(model.cpu_nanos_per_byte, deserialized.cpu_nanos_per_byte);
        assert_eq!(model.fixed_cpu_nanos, deserialized.fixed_cpu_nanos);
        let prediction2 = deserialized.predict_cost(ring_size, message_size);
        assert_eq!(prediction, prediction2);
    }

    #[test]
    fn verification_cost_model_update_test() {
        let mut model = VerificationCostModel {
            cpu_nanos_per_member: 70_000,
            cpu_nanos_per_byte: 10,
            fixed_cpu_nanos: -150_000,
            learning_rate: 1e-7,
            updates: 0,
        };
        let ring_size = 1000;
        let message_size = 16000;
        let prediction = model.predict_cost(ring_size, message_size);
        let actual_cpu_time = Duration::from_nanos(prediction + 10_000_000);
        model.update(ring_size, message_size, actual_cpu_time);
        assert!(model.cpu_nanos_per_member > 70_000);
        assert!(model.cpu_nanos_per_byte > 10);
        assert!(model.fixed_cpu_nanos > -150_000);
        assert_eq!(model.updates, 1);
    }
}
