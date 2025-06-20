# Efficient DGTOTP with Optimized Registration Strategies

# DGTOTP Experimental Code

This repository contains experimental implementations of two DGTOTP (Dynamic Group Time-based One-Time Password) schemes:

- **LWDGT** – Low-Wastage DGTOTP
- **NWDGT** – No-Wastage DGTOTP

Both schemes are implemented in C using the **OpenSSL** library and are designed to run on **Linux** systems.

## Repository Structure

```
.
├── LWDGT/     # Implementation of Low-Wastage DGTOTP
└── NWDGT/     # Implementation of No-Wastage DGTOTP
```

## Requirements

- Linux environment
- GCC or compatible compiler
- OpenSSL development libraries

### Install Dependencies (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install build-essential libssl-dev
```

## Build and Benchmark

To compile and run the benchmark for a specific scheme:

```bash
cd LWDGT    # or NWDGT
make benchmark
```

This command will build the project and run performance tests.

## Notes

- All code is for academic/research purposes.
- Make sure OpenSSL is properly installed and linked.
