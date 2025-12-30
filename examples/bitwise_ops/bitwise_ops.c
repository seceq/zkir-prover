// Bitwise operations for ZKIR proving
// Tests: AND, OR, XOR, shifts, bit manipulation
// Compile: clang -O2 -emit-llvm -c bitwise_ops.c -o bitwise_ops.bc
// Convert: zkir-llvm bitwise_ops.bc -o bitwise_ops.zkir

// Count set bits (popcount) using bitwise operations
int popcount(unsigned int x) {
    int count = 0;
    while (x) {
        count += x & 1;  // AND with 1
        x >>= 1;         // Right shift
    }
    return count;
}

// Swap nibbles using shifts and masks
unsigned int swap_nibbles(unsigned int x) {
    unsigned int low = x & 0x0F;        // AND mask
    unsigned int high = (x >> 4) & 0x0F; // Shift + AND
    return (low << 4) | high;           // Shift + OR
}

// XOR swap two values (tests XOR)
void xor_swap(int *a, int *b) {
    *a = *a ^ *b;  // XOR
    *b = *a ^ *b;
    *a = *a ^ *b;
}

// Check if power of 2 using AND
int is_power_of_2(unsigned int x) {
    return x && !(x & (x - 1));
}

int main() {
    // Test popcount: 0b10101010 = 170 has 4 bits set
    int bits = popcount(170);

    // Test swap_nibbles: 0xAB -> 0xBA (171 -> 186)
    unsigned int swapped = swap_nibbles(0xAB);

    // Test XOR swap
    int x = 5, y = 10;
    xor_swap(&x, &y);
    // Now x=10, y=5

    // Test power of 2: 16 is power of 2
    int pow2 = is_power_of_2(16);

    // Combine results: bits(4) + swapped(186) + x(10) + pow2(1) = 201
    return bits + swapped + x + pow2;
}
