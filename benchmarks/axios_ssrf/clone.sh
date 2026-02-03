#!/bin/bash
set -e

echo "Cloning Axios vulnerable version (v0.21.0)..."
git clone --depth 1 --branch v0.21.0 https://github.com/axios/axios.git axios_vuln

echo "Cloning Axios fixed version (v0.21.1)..."
git clone --depth 1 --branch v0.21.1 https://github.com/axios/axios.git axios_fixed

echo "Done! Benchmark repositories cloned:"
echo "  - axios_vuln/ (vulnerable)"
echo "  - axios_fixed/ (fixed)"
