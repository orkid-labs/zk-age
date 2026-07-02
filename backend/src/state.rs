//! Application state — tracks metrics for Thrive grant milestones.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::collections::HashSet;

pub struct AppState {
    pub proofs_generated: AtomicU64,
    pub proofs_verified: AtomicU64,
    pub zkverify_submissions: AtomicU64,
    pub unique_users: RwLock<HashSet<String>>,
    pub last_proof_at: RwLock<Option<String>>,
    pub energy_sum: RwLock<f64>,
    pub negentropy_sum: RwLock<f64>,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    pub fn new() -> Self {
        Self {
            proofs_generated: AtomicU64::new(0),
            proofs_verified: AtomicU64::new(0),
            zkverify_submissions: AtomicU64::new(0),
            unique_users: RwLock::new(HashSet::new()),
            last_proof_at: RwLock::new(None),
            energy_sum: RwLock::new(0.0),
            negentropy_sum: RwLock::new(0.0),
        }
    }

    pub fn record_proof(&self, user_id: &str, energy: f64, negentropy_bits: f64) {
        self.proofs_generated.fetch_add(1, Ordering::Relaxed);
        {
            let mut users = self.unique_users.write().expect("unique_users lock poisoned");
            users.insert(user_id.to_string());
        }
        {
            let mut ts = self.last_proof_at.write().expect("last_proof_at lock poisoned");
            *ts = Some(chrono::Utc::now().to_rfc3339());
        }
        {
            let mut sum = self.energy_sum.write().expect("energy_sum lock poisoned");
            *sum += energy;
        }
        {
            let mut sum = self.negentropy_sum.write().expect("negentropy_sum lock poisoned");
            *sum += negentropy_bits;
        }
    }

    pub fn record_verification(&self) {
        self.proofs_verified.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_zkverify_submission(&self) {
        self.zkverify_submissions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn stats(&self) -> (u64, u64, u64, u64, Option<String>, f64, f64) {
        let users = self.unique_users.read().expect("unique_users read lock poisoned").len() as u64;
        let last = self.last_proof_at.read().expect("last_proof_at read lock poisoned").clone();
        let count = self.proofs_generated.load(Ordering::Relaxed);
        let avg_energy = if count == 0 {
            0.0
        } else {
            let sum = *self.energy_sum.read().expect("energy_sum read lock poisoned");
            sum / count as f64
        };
        let total_negentropy = *self.negentropy_sum.read().expect("negentropy_sum read lock poisoned");
        (
            self.proofs_generated.load(Ordering::Relaxed),
            self.proofs_verified.load(Ordering::Relaxed),
            self.zkverify_submissions.load(Ordering::Relaxed),
            users,
            last,
            avg_energy,
            total_negentropy,
        )
    }
}
