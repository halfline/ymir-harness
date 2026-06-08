# Example Benchmark Cases

This directory is a synthetic, offline seed fixture for Ymir Harness. It is not
a historical Red Hat benchmark case. Use it to verify fixture layout, validation,
network-denied policy, and report generation before adding private or historical
pilot cases.

```bash
ymir-harness validate-cases examples/benchmark_cases/
ymir-harness run --cases examples/benchmark_cases/ --variant example
```
