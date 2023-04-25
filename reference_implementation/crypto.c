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
	for (int i = 0; i < CRYPTO_IN_SIZE; i++) {
		pt[i] ^= roundkey[i];
	}
}

static const uint8_t sbox[16] = {
	0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2,
};

/**
 * Perform S-Box Layer in Present Algorithm
 * @param s Input: Plain text to perform sbox
 */
static void sbox_layer(uint8_t s[CRYPTO_IN_SIZE])
{
	// perform substitution on the state
	for (int i = 0; i < CRYPTO_IN_SIZE; i++) {
 		s[i] = sbox[s[i] >> 4] << 4 | sbox[s[i] & 0x0F];
		// uint8_t ln = s[i] & 0xF;
		// uint8_t un = (s[i] >> 4) & 0xF;
		// s[i] = sbox[ln] | (sbox[un] << 4);
	}
}

/**
 * Perform Permutation Layer in Present Algorithm
 * @param s Input: Plain text to perform Permutation 
 */
static void pbox_layer(uint8_t s[CRYPTO_IN_SIZE])
{
	uint8_t t[CRYPTO_IN_SIZE];
	for (int i = 0; i < CRYPTO_IN_SIZE; i++)
	{
		t[i] = s[i];
	}
	
	for (int i = 0; i < CRYPTO_SIZE_IN_BITS; i++)
	{
		int old_byte_block = i/8;
		uint8_t bit_to_be_copied = getbit(t[old_byte_block], i%8);
		int new_position_of_the_bit = (i/4) + (i%4) * 16;
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
	
	for(i = 1; i <= 31; i++)
	{
		add_round_key(pt, key + 2);
		sbox_layer(pt);
		pbox_layer(pt);
		update_round_key(key, i);
	}
	
	add_round_key(pt, key + 2);
}
