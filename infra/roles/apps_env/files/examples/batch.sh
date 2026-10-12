#!/bin/bash -l
# T88 example: a CPU batch job (C and C++ with threads). Submit from a writable
# directory (your home or project; /apps is read-only), naming your project:
#   sbatch -A proj-alpha /apps/examples/batch.sh
#SBATCH -J t88-batch
#SBATCH -p cpu
#SBATCH -n 1
#SBATCH -c 4
#SBATCH --mem=4G
#SBATCH -t 00:10:00
set -eo pipefail
module load gcc/11.5
src=/apps/examples work=$PWD/t88-build-$SLURM_JOB_ID
mkdir -p "$work" && trap 'rm -rf "$work"' EXIT
gcc -O2 -o "$work/hello" "$src/hello.c"
g++ -O2 -pthread -o "$work/hello_threads" "$src/hello_threads.cpp"
"$work/hello"
"$work/hello_threads"
