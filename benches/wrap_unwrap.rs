//! Performance benchmarks for GSS wrap/unwrap operations
//!
//! Run with: cargo bench

// criterion_group! generates an undocumented `pub fn`.
#![allow(missing_docs)]

use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use fabi_kerbsec::{AuthLevel, IovWrap};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Benchmark data sizes
const SMALL_PAYLOAD: usize = 256; // Small RPC call
const MEDIUM_PAYLOAD: usize = 4096; // Typical RPC request
const LARGE_PAYLOAD: usize = 65536; // 64KB max fragment

/// Mock GSS wrapper for benchmarking without real Kerberos
struct MockGssContext {
    auth_level: AuthLevel,
    seq_num: u32,
}

impl MockGssContext {
    const fn new(auth_level: AuthLevel) -> Self {
        Self {
            auth_level,
            seq_num: 0,
        }
    }

    /// Simulate IOV wrap operation
    fn wrap_iov(&mut self, data: &[u8]) -> IovWrap {
        self.seq_num += 1;

        let (header_size, trailer_size) = match self.auth_level {
            AuthLevel::Integrity => (16, 12), // Header + MIC
            AuthLevel::Privacy => (32, 28),   // Header + padding + encrypted MIC
        };

        // Simulate header construction
        let mut header = Vec::with_capacity(header_size);
        header.extend_from_slice(&[0x05, 0x00]); // GSS header
        header.extend_from_slice(&(self.auth_level as u16).to_le_bytes());
        header.extend_from_slice(&self.seq_num.to_le_bytes());
        header.resize(header_size, 0);

        // Simulate trailer (MIC/encrypted)
        let mut trailer = Vec::with_capacity(trailer_size);
        if self.auth_level == AuthLevel::Privacy {
            // Simulate encryption overhead
            let padding = (16 - (data.len() % 16)) % 16;
            trailer.resize(padding, 0);
        }

        // Add MIC
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        header.hash(&mut hasher);
        let mic = hasher.finish().to_le_bytes();
        trailer.extend_from_slice(&mic);
        trailer.extend_from_slice(&mic[0..4]); // Extra MIC bytes

        let payload = Bytes::copy_from_slice(data);

        IovWrap {
            header: Bytes::from(header),
            payload,
            trailer: Bytes::from(trailer),
            conf: self.auth_level == AuthLevel::Privacy,
        }
    }

    /// Simulate IOV unwrap operation
    fn unwrap_iov(&mut self, wrapped: &IovWrap, _data: &[u8]) -> Result<(), &'static str> {
        // Verify header
        if wrapped.header.len() < 8 {
            return Err("Invalid header size");
        }

        // Extract and verify sequence number
        let seq_bytes = &wrapped.header[4..8];
        let seq = u32::from_le_bytes([seq_bytes[0], seq_bytes[1], seq_bytes[2], seq_bytes[3]]);

        if seq <= self.seq_num {
            return Err("Replay detected");
        }
        self.seq_num = seq;

        // Verify MIC in trailer
        if wrapped.trailer.len() < 12 {
            return Err("Invalid trailer size");
        }

        Ok(())
    }
}

fn benchmark_wrap_integrity(c: &mut Criterion) {
    let mut group = c.benchmark_group("wrap_integrity");

    for size in &[SMALL_PAYLOAD, MEDIUM_PAYLOAD, LARGE_PAYLOAD] {
        let data = vec![0x42u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function(format!("{size}_bytes"), |b| {
            let mut ctx = MockGssContext::new(AuthLevel::Integrity);
            b.iter(|| {
                let wrapped = ctx.wrap_iov(black_box(&data));
                black_box(wrapped);
            });
        });
    }

    group.finish();
}

fn benchmark_wrap_privacy(c: &mut Criterion) {
    let mut group = c.benchmark_group("wrap_privacy");

    for size in &[SMALL_PAYLOAD, MEDIUM_PAYLOAD, LARGE_PAYLOAD] {
        let data = vec![0x42u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function(format!("{size}_bytes"), |b| {
            let mut ctx = MockGssContext::new(AuthLevel::Privacy);
            b.iter(|| {
                let wrapped = ctx.wrap_iov(black_box(&data));
                black_box(wrapped);
            });
        });
    }

    group.finish();
}

fn benchmark_unwrap_integrity(c: &mut Criterion) {
    let mut group = c.benchmark_group("unwrap_integrity");

    for size in &[SMALL_PAYLOAD, MEDIUM_PAYLOAD, LARGE_PAYLOAD] {
        let data = vec![0x42u8; *size];
        let mut ctx = MockGssContext::new(AuthLevel::Integrity);
        let wrapped = ctx.wrap_iov(&data);
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function(format!("{size}_bytes"), |b| {
            b.iter(|| ctx.unwrap_iov(black_box(&wrapped), black_box(&data)));
        });
    }

    group.finish();
}

fn benchmark_unwrap_privacy(c: &mut Criterion) {
    let mut group = c.benchmark_group("unwrap_privacy");

    for size in &[SMALL_PAYLOAD, MEDIUM_PAYLOAD, LARGE_PAYLOAD] {
        let data = vec![0x42u8; *size];
        let mut ctx = MockGssContext::new(AuthLevel::Privacy);
        let wrapped = ctx.wrap_iov(&data);
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function(format!("{size}_bytes"), |b| {
            b.iter(|| ctx.unwrap_iov(black_box(&wrapped), black_box(&data)));
        });
    }

    group.finish();
}

fn benchmark_iov_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("iov_overhead");

    // Measure overhead for different payload sizes
    for size in &[256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536] {
        let data = vec![0x42u8; *size];

        group.bench_function(format!("integrity_{size}"), |b| {
            b.iter(|| {
                let mut ctx = MockGssContext::new(AuthLevel::Integrity);
                let wrapped = ctx.wrap_iov(black_box(&data));
                let overhead = wrapped.header.len() + wrapped.trailer.len();
                black_box(overhead);
            });
        });

        group.bench_function(format!("privacy_{size}"), |b| {
            b.iter(|| {
                let mut ctx = MockGssContext::new(AuthLevel::Privacy);
                let wrapped = ctx.wrap_iov(black_box(&data));
                let overhead = wrapped.header.len() + wrapped.trailer.len();
                black_box(overhead);
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    benchmark_wrap_integrity,
    benchmark_wrap_privacy,
    benchmark_unwrap_integrity,
    benchmark_unwrap_privacy,
    benchmark_iov_overhead
);

criterion_main!(benches);
