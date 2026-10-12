#!/bin/bash -l
# T88 example: the system Python 3.9 under its module name.
#   sbatch -A proj-alpha /apps/examples/python.sh
#SBATCH -J t88-python
#SBATCH -p cpu
#SBATCH -n 1
#SBATCH -c 1
#SBATCH --mem=1G
#SBATCH -t 00:05:00
set -eo pipefail
module load python/3.9
command -v python
python --version
python /apps/examples/hello.py
