// T88 example: a CUDA build and run (nvcc from module cuda/12.9, host compiler g++ from gcc/11.5).
#include <cstdio>
#include <cuda_runtime.h>

__global__ void add(const float *a, const float *b, float *c, int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) c[i] = a[i] + b[i];
}

int main() {
    const int n = 1 << 20;
    float *a, *b, *c;
    if (cudaMallocManaged(&a, n * sizeof(float)) != cudaSuccess || cudaMallocManaged(&b, n * sizeof(float)) != cudaSuccess
        || cudaMallocManaged(&c, n * sizeof(float)) != cudaSuccess) {
        std::printf("cuda FAILED: %s\n", cudaGetErrorString(cudaGetLastError()));
        return 1;
    }
    for (int i = 0; i < n; ++i) { a[i] = 1.0f; b[i] = 2.0f; }
    add<<<(n + 255) / 256, 256>>>(a, b, c, n);
    cudaError_t err = cudaDeviceSynchronize();
    int bad = 0;
    for (int i = 0; i < n && err == cudaSuccess; ++i) bad += c[i] != 3.0f;
    cudaDeviceProp p;
    cudaGetDeviceProperties(&p, 0);
    std::printf("%s: %s, %d wrong of %d (%s)\n", err == cudaSuccess && !bad ? "cuda ok" : "cuda FAILED", p.name, bad, n,
                cudaGetErrorString(err));
    cudaFree(a); cudaFree(b); cudaFree(c);
    return err == cudaSuccess && !bad ? 0 : 1;
}
