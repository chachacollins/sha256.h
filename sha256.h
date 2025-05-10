#ifndef SHA256
#define SHA256

typedef char* digest;
digest sha256_hash(char* msg, char* buff);
#endif // !SHA256

#ifdef SHA256_IMPLEMENTATION

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

// Byte swap macros for endianness conversion
#define byteSwap32(x) (((x) >> 24) | (((x)&0x00FF0000) >> 8) | (((x)&0x0000FF00) << 8) | ((x) << 24))
#define byteSwap64(x)                                                      \
	((((x) >> 56) & 0x00000000000000FF) | (((x) >> 40) & 0x000000000000FF00) | \
	 (((x) >> 24) & 0x0000000000FF0000) | (((x) >> 8) & 0x00000000FF000000) |  \
	 (((x) << 8) & 0x000000FF00000000) | (((x) << 24) & 0x0000FF0000000000) |  \
	 (((x) << 40) & 0x00FF000000000000) | (((x) << 56) & 0xFF00000000000000))

// Define a union for easy reference to a message block
union messageBlock {
    uint8_t e[64];    // View as 64 bytes
    uint32_t t[16];   // View as 16 32-bit words
    uint64_t s[8];    // View as 8 64-bit words
};

// ENUM to control state of the program
enum status {
    READ,   // Still reading input
    PAD0,   // Need to add padding but had a full block
    PAD1,   // Need to add a block of padding
    FINISH  // Finished all processing
};

// Maximum characters to read at once
#define MAXCHAR 100000

static uint32_t K[] =
    {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
// Fill the next message block with data and handle padding
bool fillMessageBlock(char* msg, union messageBlock *msgBlock, enum status *state, uint64_t *numBits, uint64_t *cursor)
{   
    uint64_t numBytes;
    int i;

    // If we've finished processing, exit
    if(*state == FINISH)
    {
        return false;
    }

    // Handle padding states
    if(*state == PAD0 || *state == PAD1)
    {
        // Clear the block
        for(i = 0; i < 64; i++)
        {
            msgBlock->e[i] = 0x00;
        }

        // Add the 1 bit if we're in PAD1 state
        if(*state == PAD1)
        {
            msgBlock->e[0] = 0x80;
        }

        // Add the message length in bits at the end of the block
        msgBlock->s[7] = byteSwap64(*numBits);
        
        // Move to FINISH state
        *state = FINISH;
        
        return true;
    }

    // Clear the message block
    memset(msgBlock->e, 0, 64);
    
    // Calculate how many bytes to read (up to 64)
    int bytesToRead = strlen(msg + *cursor) < 64 ? strlen(msg + *cursor) : 64;
    
    // Copy the next chunk of data
    if (bytesToRead > 0) {
        memcpy(msgBlock->e, msg + *cursor, bytesToRead);
    }
    
    // Update cursor position
    *cursor += bytesToRead;
    
    // Update bit count
    *numBits += bytesToRead * 8;
    
    // Handle padding
    if (bytesToRead < 56) {
        // There's room for padding and length in this block
        msgBlock->e[bytesToRead] = 0x80;  // Append 1 bit followed by zeros
        
        // Add message length at the end
        msgBlock->s[7] = byteSwap64(*numBits);
        
        // We're done after this block
        *state = FINISH;
    } 
    else if (bytesToRead < 64) {
        // Room for the 1 bit but not length
        msgBlock->e[bytesToRead] = 0x80;
        
        // We'll need another block just for the length
        *state = PAD0;
    }
    else if (bytesToRead == 64) {
        // Read a full block
        // Check if we've reached the end of the file
        if (*cursor >= strlen(msg)) {
            // Need a new block starting with 1 bit
            *state = PAD1;
        }
    }
    
    return true;
}

// Check if system is big-endian
static bool endianCheck()
{
    int num = 1;
    if(*(char *)&num == 1) {
        return false;  // Little-endian
    } else {
        return true;   // Big-endian
    }
}

// Rotate right
static uint32_t rotr(uint32_t x, uint16_t n)
{
    return (x >> n) | (x << (32 - n));
}

// Shift right
static uint32_t shr(uint32_t x, uint16_t n)
{
    return (x >> n);
}

// Message schedule functions
static uint32_t sig0(uint32_t x)
{
    return (rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3));
}

static uint32_t sig1(uint32_t x)
{
    return (rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10));
}

// Compression function parts
static uint32_t SIG0(uint32_t x)
{
    return (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22));
}

static uint32_t SIG1(uint32_t x)
{
    return (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25));
}

// Choose function
static uint32_t Ch(uint32_t x, uint32_t y, uint32_t z)
{
    return ((x & y) ^ (~(x) & z));
}

// Majority function
static uint32_t Maj(uint32_t x, uint32_t y, uint32_t z)
{
    return ((x & y) ^ (x & z) ^ (y & z));
}

digest sha256_hash(char* msg, char* buf)
{
    // Variables
    union messageBlock msgBlock;
    uint64_t numBits = 0;
    uint64_t cursor = 0;
    enum status state = READ;

    // Message schedule array
    uint32_t W[64];

    // Working variables
    uint32_t a, b, c, d, e, f, g, h;

    // Temp variables
    uint32_t T1, T2;

    // Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
    uint32_t H[8] = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    };

    int j, o;
    while(fillMessageBlock(msg, &msgBlock, &state, &numBits, &cursor))
    {
        // Prepare message schedule
        for(j = 0; j < 16; j++)
        {   
            // Handle endianness
            if(endianCheck() == true)
            {
                W[j] = msgBlock.t[j];
            }
            else
            {
                W[j] = byteSwap32(msgBlock.t[j]);
            }
        }

        // Extend the first 16 words into the remaining 48 words of W
        for (j = 16; j < 64; j++)
        {
            W[j] = sig1(W[j-2]) + W[j-7] + sig0(W[j-15]) + W[j-16];
        }

        // Initialize working variables with current hash value
        a = H[0];
        b = H[1];
        c = H[2];
        d = H[3];
        e = H[4];
        f = H[5];
        g = H[6];
        h = H[7];

        // Main loop (compression function)
        for(j = 0; j < 64; j++)
        {
            T1 = h + SIG1(e) + Ch(e, f, g) + K[j] + W[j];
            T2 = SIG0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        // Add compressed chunk to current hash value
        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }

    printf("\n=================== HASH OUTPUT ==================================\n\n");
    printf("%08x", H[0]);
    printf("%08x", H[1]);
    printf("%08x", H[2]);
    printf("%08x", H[3]);
    printf("%08x", H[4]);
    printf("%08x", H[5]);
    printf("%08x", H[6]);
    printf("%08x", H[7]);
    
    printf("\n\n==================================================================\n\n");

    char* buffer;
    if(buf) buffer = buf; 
    else buffer = (char*) malloc(sizeof(char) * 65);
    sprintf(buffer, "%08x%08x%08x%08x%08x%08x%08x%08x", 
            H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]);
    return buffer;
}
#endif
