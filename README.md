# EX-NO-7-Implement-DES-Encryption

## Aim:

To use the Data Encryption Standard (DES) algorithm for a practical application, such as securing sensitive data transmission in financial transactions.

## ALGORITHM:

1. DES is based on a symmetric key encryption technique that encrypts data in 64-bit blocks.
2. DES uses a Feistel network structure with 16 rounds of processing for encryption.
3. DES has a 64-bit key, but only 56 bits are used for encryption (the remaining 8 bits are for parity).
4. DES applies initial and final permutations along with 16 rounds of substitution and permutation transformations to produce ciphertext.

## Program:
~~~
#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef uint64_t ull;

int IP[64] = {
58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7
};

int FP[64] = {
40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25
};

int E[48] = {
32,1,2,3,4,5,4,5,6,7,8,9,
8,9,10,11,12,13,12,13,14,15,16,17,
16,17,18,19,20,21,20,21,22,23,24,25,
24,25,26,27,28,29,28,29,30,31,32,1
};

int P[32] = {
16,7,20,21,29,12,28,17,
1,15,23,26,5,18,31,10,
2,8,24,14,32,27,3,9,
19,13,30,6,22,11,4,25
};

int PC1[56] = {
57,49,41,33,25,17,9,1,58,50,42,34,26,18,
10,2,59,51,43,35,27,19,11,3,60,52,44,36,
63,55,47,39,31,23,15,7,62,54,46,38,30,22,
14,6,61,53,45,37,29,21,13,5,28,20,12,4
};

int PC2[48] = {
14,17,11,24,1,5,3,28,15,6,21,10,
23,19,12,4,26,8,16,7,27,20,13,2,
41,52,31,37,47,55,30,40,51,45,33,48,
44,49,39,56,34,53,46,42,50,36,29,32
};

int S[8][4][16] = {
{
{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
},
{
{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
{0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
},
{
{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
{13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
},
{
{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
},
{
{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
{4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
},
{
{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
{9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
},
{
{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
{1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
},
{
{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
{7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
}
};

int shift[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

ull permute(ull x, int *table, int n, int bits) {
    ull r = 0;
    for (int i = 0; i < n; i++)
        r = (r << 1) | ((x >> (bits - table[i])) & 1ULL);
    return r;
}

ull subkeys[16];

void makeKeys(ull key) {
    ull k = permute(key, PC1, 56, 64);
    unsigned int c = (k >> 28) & 0x0FFFFFFF;
    unsigned int d = k & 0x0FFFFFFF;

    for (int i = 0; i < 16; i++) {
        c = ((c << shift[i]) | (c >> (28 - shift[i]))) & 0x0FFFFFFF;
        d = ((d << shift[i]) | (d >> (28 - shift[i]))) & 0x0FFFFFFF;
        subkeys[i] = permute(((ull)c << 28) | d, PC2, 48, 56);
    }
}

unsigned int f(unsigned int r, ull key) {
    ull x = permute(r, E, 48, 32) ^ key;
    unsigned int out = 0;

    for (int i = 0; i < 8; i++) {
        int b = (x >> (42 - 6 * i)) & 63;
        int row = ((b & 32) >> 4) | (b & 1);
        int col = (b >> 1) & 15;
        out = (out << 4) | S[i][row][col];
    }
    return (unsigned int)permute(out, P, 32, 32);
}

ull DES(ull block, int decrypt) {
    ull x = permute(block, IP, 64, 64);
    unsigned int l = x >> 32, r = (unsigned int)x;

    for (int i = 0; i < 16; i++) {
        unsigned int temp = r;
        r = l ^ f(r, subkeys[decrypt ? 15 - i : i]);
        l = temp;
    }

    return permute(((ull)r << 32) | l, FP, 64, 64);
}

int main(void) {
    char text[9];
    char keyText[9];
    ull key = 0, block = 0, encrypted, decrypted;

    printf("Enter 8-character plaintext: ");
    if (scanf("%8s", text) != 1 || strlen(text) != 8) {
        printf("Plaintext must contain exactly 8 characters.\n");
        return 1;
    }

    printf("Enter 8-character key: ");
    if (scanf("%8s", keyText) != 1 || strlen(keyText) != 8) {
        printf("Key must contain exactly 8 characters.\n");
        return 1;
    }

    for (int i = 0; i < 8; i++) {
        key = (key << 8) | (unsigned char)keyText[i];
        block = (block << 8) | (unsigned char)text[i];
    }

    makeKeys(key);

    encrypted = DES(block, 0);
    decrypted = DES(encrypted, 1);

    printf("Encrypted text: %016llX\n", encrypted);
    printf("Decrypted text: ");

    for (int i = 7; i >= 0; i--)
        putchar((int)((decrypted >> (i * 8)) & 255));

    printf("\n");
    return 0;
}
~~~
## Output:
<img width="1917" height="687" alt="image" src="https://github.com/user-attachments/assets/e5228490-66da-4194-b215-1a47f0d19f26" />



## Result:
  The program is executed successfully.

