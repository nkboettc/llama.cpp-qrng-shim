# llama.cpp QRNG entropy intervention

This repository contains a minimal, source-level modification used to
introduce quantum-derived randomness into the stochastic token sampling
process of `llama.cpp`.

The intervention substitutes a quantum random number source for the
pseudo-random number generator used during sampling. It does not modify
model weights, logits, decoding strategy, or sampling parameters.

The code was developed to support experimental and creative research on
the provenance of randomness in large language model generation, and is
intended to be inspected rather than used as a standalone tool.

## Scope

- Self-contained source files (`qrng_shim.cpp` and `qrng_shim.h`)
- Designed to integrate at the level of entropy sourcing only
- No changes to model architecture or learned distributions
- No claims about output quality or performance

## Relationship to the accompanying study

This code supports the QRNG-per-token condition described in the
accompanying manuscript. Generation orchestration, analysis code, and
generated corpora are archived separately.

This repository exists solely to delimit and disclose the point at which
quantum randomness enters the inference process.
