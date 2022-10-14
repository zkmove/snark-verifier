# PLONK Verifier

Generic PLONK verifier.

## SRS

Note that if aggregating snarks with different `K` params size, you should generate the largest srs necessarily and then `downgrade` to the smaller param sizes so that the first two points are the same for all srs files.
