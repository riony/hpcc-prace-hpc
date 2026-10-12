/* T88 example: MPI across nodes (mpicc from module openmpi/4.1, started by mpirun in mpi.sh).
 * Every rank sends 1 MiB to rank 0 and reports its host; rank 0 prints the world size and the
 * number of distinct hosts. A rank that started alone (world size 1) means the launch did not
 * connect the ranks: the job script treats that as a failure. */
#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BYTES (1 << 20)

int main(int argc, char **argv) {
    int rank, size, len, distinct = 0;
    char name[MPI_MAX_PROCESSOR_NAME] = {0};
    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);
    MPI_Get_processor_name(name, &len);
    char *all = calloc((size_t)size, MPI_MAX_PROCESSOR_NAME);
    MPI_Gather(name, MPI_MAX_PROCESSOR_NAME, MPI_CHAR, all, MPI_MAX_PROCESSOR_NAME, MPI_CHAR, 0, MPI_COMM_WORLD);
    char *buf = malloc(BYTES);
    long sum = 0;
    if (rank == 0) {
        for (int r = 1; r < size; ++r) {
            MPI_Recv(buf, BYTES, MPI_CHAR, r, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
            sum += buf[BYTES - 1];
        }
        for (int i = 0; i < size; ++i) {
            int seen = 0;
            for (int j = 0; j < i; ++j)
                seen |= !strcmp(all + (size_t)i * MPI_MAX_PROCESSOR_NAME, all + (size_t)j * MPI_MAX_PROCESSOR_NAME);
            distinct += !seen;
            printf("rank %d on %s\n", i, all + (size_t)i * MPI_MAX_PROCESSOR_NAME);
        }
        printf("mpi: size=%d hosts=%d messages=%ld\n", size, distinct, sum);
    } else {
        memset(buf, 1, BYTES);
        MPI_Send(buf, BYTES, MPI_CHAR, 0, 0, MPI_COMM_WORLD);
    }
    free(buf);
    free(all);
    MPI_Finalize();
    return 0;
}
