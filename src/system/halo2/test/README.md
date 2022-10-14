In `plonk-verifier` root directory:

1. Create `params` folder. Do not reuse params generated from other versions of `halo2_proofs` for now.

2. Create `configs/verify_circuit.config`.

3. Create `src/system/halo2/test/data` directory. Then run

For single evm circuit verification:

```
cargo test --release -- --nocapture system::halo2::test::kzg::halo2::zkevm::test_shplonk_bench_evm_circuit --exact
```

For evm circuit + state circuit aggregation:

```
cargo test --release -- --nocapture system::halo2::test::kzg::halo2::zkevm::test_shplonk_bench_evm_and_state --exact
```
