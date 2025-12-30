// Fibonacci computation for ZKIR proving
// Compile: clang -O2 -emit-llvm -S fibonacci.c -o fibonacci.ll
// Convert: zkir-llvm translate fibonacci.ll -o fibonacci.zkbc

// Iterative fibonacci to avoid deep recursion
int fibonacci(int n) {
    if (n <= 1) {
        return n;
    }

    int prev = 0;
    int curr = 1;

    for (int i = 2; i <= n; i++) {
        int next = prev + curr;
        prev = curr;
        curr = next;
    }

    return curr;
}

int main() {
    // Compute fib(10) = 55
    int result = fibonacci(10);
    return result;
}
