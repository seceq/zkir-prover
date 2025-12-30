// Array operations for ZKIR proving
// Tests: Memory load/store, array indexing, pointers
// Compile: clang -O1 -fno-vectorize -fno-slp-vectorize -emit-llvm -c array_sum.c -o array_sum.bc
// Convert: zkir-llvm array_sum.bc -o array_sum.zkir

// Sum array elements (tests indexed memory access)
int sum_array(int *arr, int len) {
    int sum = 0;
    for (int i = 0; i < len; i++) {
        sum += arr[i];
    }
    return sum;
}

// Find maximum in array (tests comparison + memory)
int find_max(int *arr, int len) {
    if (len <= 0) return 0;

    int max = arr[0];
    for (int i = 1; i < len; i++) {
        int val = arr[i];
        if (val > max) {
            max = val;
        }
    }
    return max;
}

// Reverse array in place (tests read + write to same array)
void reverse_array(int *arr, int len) {
    int left = 0;
    int right = len - 1;
    while (left < right) {
        int temp = arr[left];
        arr[left] = arr[right];
        arr[right] = temp;
        left++;
        right--;
    }
}

// Global array - statically initialized, aligned
int nums[5] = {1, 2, 3, 4, 5};

int main() {
    // Test sum: 1+2+3+4+5 = 15
    int total = sum_array(nums, 5);

    // Test max: max(1,2,3,4,5) = 5
    int maximum = find_max(nums, 5);

    // Test reverse (modifies nums to {5,4,3,2,1})
    reverse_array(nums, 5);
    int first_after_reverse = nums[0];  // Should be 5

    // Combine: 15 + 5 + 5 = 25
    return total + maximum + first_after_reverse;
}
