// Loop sum program for ZKIR proving - tests loop unrolling
// Compile: clang -O2 -emit-llvm -S loop_sum.c -o loop_sum.ll
// Convert: zkir-llvm translate loop_sum.ll -o loop_sum.zkbc

int sum_to_n(int n) {
    int sum = 0;
    for (int i = 1; i <= n; i++) {
        sum += i;
    }
    return sum;
}

int main() {
    // Sum 1 to 10 = 55
    int result = sum_to_n(10);
    return result;
}
