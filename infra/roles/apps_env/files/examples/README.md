# Job examples

Copy nothing: submit from a writable directory (your home, or your project's directory under
`/projects`), because `/apps` is read-only and jobs write their output where they were submitted.
Every job names its project with `-A` (`proj-alpha`, `proj-beta` or `proj-ops`; `sacctmgr -nP show
assoc user=$USER format=account` lists yours).

```bash
cd ~                                            # or /projects/<your project>
module avail                                    # gcc/11.5 cuda/12.9 openmpi/4.1 python/3.9
sbatch -A proj-alpha /apps/examples/batch.sh    # CPU: C and C++ with threads
sbatch -A proj-alpha /apps/examples/array.sh    # job array, 4 tasks
sbatch -A proj-alpha /apps/examples/python.sh   # Python 3.9
sbatch -A proj-alpha /apps/examples/gpu.sh      # nvcc build and run on one V100
sbatch -A proj-alpha /apps/examples/mpi.sh      # MPI: 2 GPU nodes, 1 rank each, TCP
srun -A proj-alpha -p debug -n 1 -c 2 --mem=2G -t 10 --pty bash -l     # interactive, CPU node
squeue --me; cat slurm-<jobid>.out
```

Rules the scripts follow: CPU-only work goes to `cpu`; a job on a GPU node (`gpu`, or `debug`
with a GPU) asks for at least one GPU and at most 4 CPUs and 90 GiB per GPU; `debug` (30 min at
most) refuses `--exclusive` and `--mem=0`. CUDA is only on the GPU nodes: load `cuda/12.9` inside
a GPU job. MPI uses TCP on the pod network (`mpi.sh` sets it); InfiniBand is not available yet.
