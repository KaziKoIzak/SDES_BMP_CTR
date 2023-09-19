#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#pragma pack(1)

typedef struct
{
    uint16_t type;
    uint32_t size;
    uint16_t reserved1;
    uint16_t reserved2;
    uint32_t offset;
} BMPHeader;

typedef struct
{
    uint32_t size;
    int32_t width;
    int32_t height;
    uint16_t planes;
    uint16_t bitCount;
    uint32_t compression;
    uint32_t imageSize;
    int32_t xPixelsPerMeter;
    int32_t yPixelsPerMeter;
    uint32_t colorsUsed;
    uint32_t colorsImportant;
} BMPInfoHeader;

// Initial permutation table
int IP[] = {2, 6, 3, 1, 4, 8, 5, 7};

// Final permutation table (inverse of initial permutation)
int FP[] = {4, 1, 3, 5, 7, 2, 8, 6};

int key[] = {0, 1, 0, 1, 0, 0, 0, 1, 0, 1};

int subKey1[] = {0, 0, 0, 0, 0, 0, 0, 0};

int subKey2[] = {0, 0, 0, 0, 0, 0, 0, 0};

int keySaver[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

int plaintext[] = {0, 0, 0, 0, 0, 0, 0, 0};

int plaintext2[] = {0, 0, 0, 0, 0, 0, 0, 0};

int ciphertext[] = {0, 0, 0, 0, 0, 0, 0, 0};

int ciphertext2[] = {0, 0, 0, 0, 0, 0, 0, 0};

int nonce[] = {1, 1, 1, 0, 0, 1, 0, 0};

int Counter[] = {0, 0, 0, 0, 0, 0, 0, 0};

char counter = 0x00;

// Expansion permutation table
int EP[] = {4, 1, 2, 3, 2, 3, 4, 1};

// P4 permutation table
int P4[] = {2, 4, 3, 1};

// S-boxes (S0 and S1)
int S0[4][4] = {{1, 0, 3, 2}, {3, 2, 1, 0}, {0, 2, 1, 3}, {3, 1, 3, 2}};
int S1[4][4] = {{0, 1, 2, 3}, {2, 0, 1, 3}, {3, 0, 1, 0}, {2, 1, 0, 3}};

int P8[] = {6, 3, 7, 4, 8, 5, 10, 9};

int P10[] = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};

char binaryArrayToChar(int *binaryArray)
{
    char character = 0;
    for (int i = 0; i < 8; i++)
    {
        character |= binaryArray[i] << (7 - i);
    }
    return character;
}

void charToBinary(char c, int *binaryArray)
{
    for (int i = 7; i >= 0; i--)
    {
        binaryArray[i] = (c >> (7 - i)) & 1;
    }
}

void combine2BitArrays(int *array1, int *array2, int *result)
{
    for (int i = 0; i < 2; i++)
    {
        result[i] = array1[i];
        result[i + 2] = array2[i];
    }
}

void finalPermutation(int *plaintext)
{
    int output[8];

    for (int i = 0; i < 8; i++)
    {
        output[i] = plaintext[FP[i] - 1];
    }

    for (int i = 0; i < 8; i++)
    {
        plaintext[i] = output[i];
    }
}

void circularLeftShift(int *key, int bits, int keySize)
{
    int leftHalf[5];
    int rightHalf[5];

    // Divide the key into two 5-bit halves
    for (int i = 0; i < 5; i++)
    {
        leftHalf[i] = key[i];
        rightHalf[i] = key[i + 5];
    }

    // Perform left shift on both halves
    for (int i = 0; i < bits; i++)
    {
        int tempLeft = leftHalf[0];
        int tempRight = rightHalf[0];

        for (int j = 0; j < 4; j++)
        {
            leftHalf[j] = leftHalf[j + 1];
            rightHalf[j] = rightHalf[j + 1];
        }

        leftHalf[4] = tempLeft;
        rightHalf[4] = tempRight;
    }

    // Recombine the two halves
    for (int i = 0; i < 5; i++)
    {
        key[i] = leftHalf[i];
        key[i + 5] = rightHalf[i];
    }
}

void p8Permutation(int *key)
{
    int output[8];

    for (int i = 0; i < 8; i++)
    {
        output[i] = key[P8[i] - 1];
    }

    for (int i = 0; i < 8; i++)
    {
        key[i] = output[i];
    }
}

void initialPermutation(int *plaintext)
{
    int output[8];

    for (int i = 0; i < 8; i++)
    {
        output[i] = plaintext[IP[i] - 1];
    }

    for (int i = 0; i < 8; i++)
    {
        plaintext[i] = output[i];
    }
}

void expansionPermutation(int *rightHalf)
{
    int output[8];

    for (int i = 0; i < 8; i++)
    {
        output[i] = rightHalf[EP[i] - 1];
    }

    for (int i = 0; i < 8; i++)
    {
        rightHalf[i] = output[i];
    }
}

void xorArrays(int *arr1, int *arr2, int size, int *result)
{
    for (int i = 0; i < size; i++)
    {
        result[i] = arr1[i] ^ arr2[i];
    }
}

void p4Permutation(int *input)
{
    int output[4];

    for (int i = 0; i < 4; i++)
    {
        output[i] = input[P4[i] - 1];
    }

    for (int i = 0; i < 4; i++)
    {
        input[i] = output[i];
    }
}

void xor4BitWithLHS(int *lhs, int *input)
{
    for (int i = 0; i < 4; i++)
    {
        lhs[i] ^= input[i];
    }
}

void combineArrays(int *array1, int *array2, int *result)
{
    for (int i = 0; i < 4; i++)
    {
        result[i] = array1[i];
        result[i + 4] = array2[i];
    }
}

void sBox(int *input, int sBox[4][4], int *output)
{
    int row = input[0] * 2 + input[3];
    int col = input[1] * 2 + input[2];
    int value = sBox[row][col];

    // Convert value to binary (2 bits)
    output[0] = (value >> 1) & 1;
    output[1] = value & 1;
}

void swapSides(int *array, int size)
{
    for (int i = 0; i < size / 2; i++)
    {
        int temp = array[i];
        array[i] = array[i + size / 2];
        array[i + size / 2] = temp;
    }
}

void copyArray(int *source, int *destination, int size)
{
    for (int i = 0; i < size; i++)
    {
        destination[i] = source[i];
    }
}

void subKey(int *key, int *keeper, int numBits)
{
    circularLeftShift(key, numBits, 10);
    copyArray(key, keeper, 10);
    p8Permutation(key);
}

void Encrypt()
{
    int leftHalf[4];
    int rightHalf[4];
    int result[8];
    int group1[4];
    int group2[4];
    int results[4];
    int combinedArray[8];
    int outputs[2]; // Array to store the result
    int outputss[2];
    int leftHandCopy[4];
    int rightHandCopy[4];

    initialPermutation(plaintext);

    for (int i = 0; i < 2; i++)
    {
        if (i == 0)
        {
            copyArray(subKey1, key, 8);
        }
        else
        {
            copyArray(subKey2, key, 8);
        }

        // Split the plaintext into two 4-bit halves
        for (int i = 0; i < 4; i++)
        {
            leftHalf[i] = plaintext[i];
            rightHalf[i] = plaintext[i + 4];
        }

        copyArray(leftHalf, leftHandCopy, 4);
        copyArray(rightHalf, rightHandCopy, 4);

        expansionPermutation(rightHalf);

        xorArrays(rightHalf, key, 8, result);

        for (int i = 0; i < 4; i++)
        {
            group1[i] = result[i];
            group2[i] = result[i + 4];
        }

        sBox(group1, S0, outputs);
        sBox(group2, S1, outputss);

        // Combine the results back into a 4-bit array

        combine2BitArrays(outputs, outputss, results);

        p4Permutation(results);

        xor4BitWithLHS(leftHandCopy, results);

        combineArrays(leftHandCopy, rightHandCopy, combinedArray);

        if (i == 0)
        {
            swapSides(combinedArray, 8);
            copyArray(combinedArray, plaintext, 8);
        }
    }

    finalPermutation(combinedArray);

    copyArray(combinedArray, ciphertext, 8);
}

void Decrypt()
{
    int leftHalf[4];
    int rightHalf[4];
    int result[8];
    int group1[4];
    int group2[4];
    int results[4];
    int combinedArray[8];
    int outputs[2]; // Array to store the result
    int outputss[2];
    int leftHandCopy[4];
    int rightHandCopy[4];

    initialPermutation(ciphertext);

    for (int i = 0; i < 2; i++)
    {
        if (i == 0)
        {
            copyArray(subKey2, key, 8);
        }
        else
        {
            copyArray(subKey1, key, 8);
        }

        // Split the plaintext into two 4-bit halves
        for (int i = 0; i < 4; i++)
        {
            leftHalf[i] = ciphertext[i];
            rightHalf[i] = ciphertext[i + 4];
        }

        copyArray(leftHalf, leftHandCopy, 4);
        copyArray(rightHalf, rightHandCopy, 4);

        expansionPermutation(rightHalf);

        xorArrays(rightHalf, key, 8, result);

        for (int i = 0; i < 4; i++)
        {
            group1[i] = result[i];
            group2[i] = result[i + 4];
        }

        sBox(group1, S0, outputs);
        sBox(group2, S1, outputss);

        // Combine the results back into a 4-bit array

        combine2BitArrays(outputs, outputss, results);

        p4Permutation(results);

        xor4BitWithLHS(leftHandCopy, results);

        combineArrays(leftHandCopy, rightHandCopy, combinedArray);

        if (i == 0)
        {
            swapSides(combinedArray, 8);
            copyArray(combinedArray, ciphertext, 8);
        }
    }

    finalPermutation(combinedArray);

    copyArray(combinedArray, plaintext, 8);
}

void encryptPixels(unsigned char *pixels, int size)
{
    for (int i = 0; i < size; i++)
    {
        charToBinary(counter, Counter);
        xorArrays(Counter, nonce, 8, plaintext);
        charToBinary(pixels[i], plaintext2);
        Encrypt();
        xorArrays(ciphertext, plaintext2, 8, ciphertext);
        pixels[i] = binaryArrayToChar(ciphertext);
        counter++;
    }
}

void decryptPixels(unsigned char *pixels, int size)
{
    for (int i = 0; i < size; i++)
    {
        charToBinary(counter, Counter);
        xorArrays(Counter, nonce, 8, plaintext);
        charToBinary(pixels[i], plaintext2);
        Encrypt();
        xorArrays(ciphertext, plaintext2, 8, ciphertext);
        pixels[i] = binaryArrayToChar(ciphertext);
        counter++;
    }
}

int main()
{
    char character;
    int output[10];
    int count = 0;
    int i = 0;
    for (int i = 0; i < 10; i++)
    {
        output[i] = key[P10[i] - 1];
    }

    for (int i = 0; i < 10; i++)
    {
        key[i] = output[i];
    }

    subKey(key, keySaver, 1);
    copyArray(key, subKey1, 8);

    subKey(keySaver, key, 2);
    copyArray(keySaver, key, 8);
    copyArray(key, subKey2, 8);

    FILE *input_file = fopen("penguin.bmp", "rb");
    FILE *output_file = fopen("cipher.bmp", "wb");

    if (!input_file || !output_file)
    {
        printf("Error opening files\n");
        return 1;
    }

    BMPHeader header;
    BMPInfoHeader infoHeader;

    fread(&header, sizeof(BMPHeader), 1, input_file);
    fread(&infoHeader, sizeof(BMPInfoHeader), 1, input_file);

    // Read pixel data
    int pixelDataSize = infoHeader.imageSize;
    unsigned char *pixels = (unsigned char *)malloc(pixelDataSize);
    fread(pixels, pixelDataSize, 1, input_file);

    // Encrypt the pixel data
    encryptPixels(pixels, pixelDataSize);

    // Write header and infoHeader
    fwrite(&header, sizeof(BMPHeader), 1, output_file);
    fwrite(&infoHeader, sizeof(BMPInfoHeader), 1, output_file);

    // Write encrypted pixel data
    fwrite(pixels, pixelDataSize, 1, output_file);

    fclose(input_file);
    fclose(output_file);

    free(pixels);

    input_file = fopen("Cipher.bmp", "rb");
    output_file = fopen("penguin.bmp", "wb");

    if (!input_file || !output_file)
    {
        printf("Error opening files\n");
        return 1;
    }

    fread(&header, sizeof(BMPHeader), 1, input_file);
    fread(&infoHeader, sizeof(BMPInfoHeader), 1, input_file);

    // Read pixel data
    pixelDataSize = infoHeader.imageSize;
    pixels = (unsigned char *)malloc(pixelDataSize);
    fread(pixels, pixelDataSize, 1, input_file);
    counter = 0x00;

    // Encrypt the pixel data
    decryptPixels(pixels, pixelDataSize);

    // Write header and infoHeader
    fwrite(&header, sizeof(BMPHeader), 1, output_file);
    fwrite(&infoHeader, sizeof(BMPInfoHeader), 1, output_file);

    // Write encrypted pixel data
    fwrite(pixels, pixelDataSize, 1, output_file);

    fclose(input_file);
    fclose(output_file);

    free(pixels);

    return 0;
}