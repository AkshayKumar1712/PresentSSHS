#include "crypto.h"
#include "stdio.h"
#define CRYPTO_SIZE_IN_BITS 64

/**
 * Get the bit value of byte at bit_position.
 * @param byte Input: byte value
 * @param bit Output: bit value
 */
static uint8_t getbit(uint8_t byte, uint8_t bit)
{
	return byte >> bit & 0x1;
}

/**
 * Copy the bit value to a new position in a byte array.
 * @param byte byte array
 * @param new_position_of_the_bit bit position to which the bit needs to be copied
 * @param new_bit bit value in new position
 */

static void cpybitArr(uint8_t* byte, int new_position_of_the_bit, uint8_t new_bit)
{
    int new_byte_block = new_position_of_the_bit/8;
    int bit_position_to_replace = new_position_of_the_bit % 8;
	byte[new_byte_block] &= ~(1 << bit_position_to_replace);    //clear the bit
	byte[new_byte_block] |= (new_bit << bit_position_to_replace);   //set the bit
}

/**
 * Perform RoundKey Layer in Present Algorithm
 * @param pt Input: Plain Text
 * @param key Input: Key to perform Add Round Key
 */
static void add_round_key(uint8_t pt[CRYPTO_IN_SIZE], uint8_t roundkey[CRYPTO_IN_SIZE])
{
	pt[0] ^= roundkey[0];
	pt[1] ^= roundkey[1];
	pt[2] ^= roundkey[2];
	pt[3] ^= roundkey[3];
	pt[4] ^= roundkey[4];
	pt[5] ^= roundkey[5];
	pt[6] ^= roundkey[6];
	pt[7] ^= roundkey[7];
}

static const uint8_t sbox[16] = {
	0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2,
};

//pLayer positions for every bit according to the formula - (i/4) + (i%4) * 16
static const uint8_t pLayer[] = {0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51,
                    4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55,
                    8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
                    12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63};

/**
 * Perform S-Box Layer in Present Algorithm
 * @param s Input: Plain text to perform sbox
 */
static void sbox_layer(uint8_t s[CRYPTO_IN_SIZE])
{
	// perform substitution on the state
	for (int i = 0; i < CRYPTO_IN_SIZE; i++) {
		uint8_t lower_nibble = s[i] & 0xF;
		uint8_t upper_nibble = (s[i] >> 4) & 0xF;
		s[i] = sbox[lower_nibble] | (sbox[upper_nibble] << 4);
	}
}

/**
 * Perform Permutation Layer in Present Algorithm
 * @param s Input: Plain text to perform Permutation 
 */
static void pbox_layer(uint8_t s[CRYPTO_IN_SIZE])
{
	uint8_t temp[CRYPTO_IN_SIZE];
	memcpy(temp, s, CRYPTO_IN_SIZE);
	
	uint8_t new_position_of_the_bit = 0, bit_to_be_copied = 0;
	for (int i = 0; i < CRYPTO_SIZE_IN_BITS; i++)
	{
		bit_to_be_copied = getbit(temp[i/8], i%8);
		new_position_of_the_bit = pLayer[i];	//precomputed the new position instead of computing it
		cpybitArr(s, new_position_of_the_bit, bit_to_be_copied);
	}
}


static void update_round_key(uint8_t key[CRYPTO_KEY_SIZE], const uint8_t r)
{
	//
	// There is no need to edit this code
	//
	uint8_t tmp = 0;
	const uint8_t tmp2 = key[2];
	const uint8_t tmp1 = key[1];
	const uint8_t tmp0 = key[0];
	
	// rotate right by 19 bit
	key[0] = key[2] >> 3 | key[3] << 5;
	key[1] = key[3] >> 3 | key[4] << 5;
	key[2] = key[4] >> 3 | key[5] << 5;
	key[3] = key[5] >> 3 | key[6] << 5;
	key[4] = key[6] >> 3 | key[7] << 5;
	key[5] = key[7] >> 3 | key[8] << 5;
	key[6] = key[8] >> 3 | key[9] << 5;
	key[7] = key[9] >> 3 | tmp0 << 5;
	key[8] = tmp0 >> 3   | tmp1 << 5;
	key[9] = tmp1 >> 3   | tmp2 << 5;
	
	// perform sbox lookup on MSbits
	tmp = sbox[key[9] >> 4];
	key[9] &= 0x0F;
	key[9] |= tmp << 4;
	
	// XOR round counter k19 ... k15
	key[1] ^= r << 7;
	key[2] ^= r >> 1;
}

void crypto_func(uint8_t pt[CRYPTO_IN_SIZE], uint8_t key[CRYPTO_KEY_SIZE])
{
	uint8_t i = 0;
	
	// Steps for reference Implementation
	for(i = 1; i <= 31; i++)
	{
		add_round_key(pt, key + 2);
		sbox_layer(pt);
		pbox_layer(pt);
		update_round_key(key, i);
	}
	
	add_round_key(pt, key + 2);
}
