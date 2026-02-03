#!/bin/bash
set -e

echo "Cloning Pug vulnerable version (pug@3.0.0)..."
git clone --depth 1 --branch pug@3.0.0 https://github.com/pugjs/pug.git pug_vuln

echo "Cloning Pug fixed version (pug@3.0.1)..."
git clone --depth 1 --branch pug@3.0.1 https://github.com/pugjs/pug.git pug_fixed

echo "Done! Benchmark repositories cloned:"
echo "  - pug_vuln/ (vulnerable)"
echo "  - pug_fixed/ (fixed)"
