#!/bin/bash -l
# T88 example: build a CUDA program with nvcc and run it on one V100. A job on a GPU node asks
# for at least one GPU and at most 4 CPUs and 90 GiB per GPU.
#   sbatch -A proj-alpha /apps/examples/gpu.sh
#SBATCH -J t88-gpu
#SBATCH -p gpu
#SBATCH --gres=gpu:1
#SBATCH -c 4
#SBATCH --mem=32G
#SBATCH -t 00:10:00
set -eo pipefail
module load gcc/11.5 cuda/12.9
src=/apps/examples work=$PWD/t88-build-$SLURM_JOB_ID
mkdir -p "$work" && trap 'rm -rf "$work"' EXIT
nvcc --version | tail -2
nvcc -ccbin g++ -arch=sm_70 -o "$work/vector_add" "$src/vector_add.cu"   # sm_70: Volta (V100)
nvidia-smi -L                       # only this job's GPU
"$work/vector_add"
