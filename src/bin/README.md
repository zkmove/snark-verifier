```
cargo run --bin evm-verifier-with-aggregation --release -- --nocapture
```

Workflow:

1. User supplies a list of `Circuit<Fr>` instances and a list of public inputs for these circuits.

2. Program generates vkey and pkey for each circuit.

   - [Todo] currently there is no way to write vkey or pkey: https://github.com/zcash/halo2/issues/443

3. Program generates proofs based on given instances, retrieving cached proof when it exists and cached instances match. Caches proofs and instances.

   - Verifies proofs just for safety.
   - The data of params, vkey, proof, instances is compiled into a `Snark` object.

4. `Snark` objects are use to construct aggregation circuit. We expose the target circuit public inputs as public inputs to aggregation circuit so that the evm circuit has access to them as private inputs (passed in calldata).
