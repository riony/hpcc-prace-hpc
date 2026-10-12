#!/bin/bash -l
# T88 example: a job array, four small CPU tasks; one output file per task.
#   sbatch -A proj-alpha /apps/examples/array.sh
#SBATCH -J t88-array
#SBATCH -p cpu
#SBATCH --array=1-4
#SBATCH -n 1
#SBATCH -c 1
#SBATCH --mem=1G
#SBATCH -t 00:05:00
#SBATCH -o t88-array-%A_%a.out
set -eo pipefail
module load python/3.9
python /apps/examples/hello.py "$SLURM_ARRAY_TASK_ID"
