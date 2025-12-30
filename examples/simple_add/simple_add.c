// Simple addition program for ZKIR proving
// Compile: clang -O2 -emit-llvm -S simple_add.c -o simple_add.ll
// Convert: zkir-llvm translate simple_add.ll -o simple_add.zkbc

int main() {
    int a = 10;
    int b = 32;
    int sum = a + b;
    return sum;  // Returns 42
}
