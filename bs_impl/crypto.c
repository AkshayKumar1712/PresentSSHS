#include "crypto.h"


static int8_t getbit(uint8_t byte, uint8_t bit)
{
	return byte >> bit & 0x1;
}



static const bs_reg_t onesMask = 0XFFFFFFFF;
/**
 * Bring normal buffer into bitsliced form
 * @param pt Input: state_bs in normal form
 * @param state_bs Output: Bitsliced state
 */
static void enslice(const uint8_t pt[CRYPTO_IN_SIZE * BITSLICE_WIDTH], bs_reg_t state_bs[CRYPTO_IN_SIZE_BIT])
{
	// INSERT YOUR CODE HERE AND DELETE THIS COMMENT
	int k = 0;
    int count=0;
    
    for (int i = 0; i < CRYPTO_IN_SIZE * BITSLICE_WIDTH; i++) {
        uint8_t byte = pt[i];
        uint32_t bitadd;
        
        for (int j = 0; j < 8; j++) {
            if(i<8){
                state_bs[i * 8 + (7-j)] = (byte >> (7 - j)) & 0x01;
            } else{
                 bitadd = (byte >> (7 - j)) & 0x01;
                 state_bs[count * 8 + (7-j)] = state_bs[count * 8 + (7-j)] | (bitadd<<k);
            }
 
        }

		if(count<7)
			++count;
		else 
			count=0;
		if(i!=0 && (i+1)%8==0)
		++k;
    }
}

/**
 * Bring bitsliced buffer into normal form
 * @param state_bs Input: Bitsliced state
 * @param pt Output: state_bs in normal form
 */
static void unslice(const bs_reg_t state_bs[CRYPTO_IN_SIZE_BIT], uint8_t pt[CRYPTO_IN_SIZE * BITSLICE_WIDTH])
{
	uint32_t test=1;
    uint32_t temp[8];
    int pos;
    
    int result_index=0;
    
    // K value depends on number of bits in each array element
    for(int k=0;k<32;++k){
        for (int i = 0; i < 8; i++) {
            pt[result_index+i];
            // printf("\n");
            pos=0;
            for (int j = 0; j < 8; j++) {
                temp[j]=(test<<k & state_bs[(i*8) + j])>>k;
                // printf("%u ", temp[j]);
            
                pt[result_index+i] = pt[result_index+i] | temp[j]<<pos;
                ++pos;
            
            }
        }
        result_index+=8; //change to 8 for code
    }
	
}

static inline void present_sbox(bs_reg_t *Y0, bs_reg_t *Y1, bs_reg_t *Y2, bs_reg_t *Y3, const bs_reg_t X0, const bs_reg_t X1, const bs_reg_t X2, const bs_reg_t X3) 
{
	*Y0 = X0 ^ (X1 & X2) ^ X2 ^ X3;
	*Y1 = (X0 & X2 & X1) ^ (X0 & X3 & X1) ^ (X1 & X3) ^ X1 ^ (X0 & X2 & X3) ^ (X2 & X3) ^ X3;
	*Y2 = (X0 & X1) ^ (X0 & X3 & X1) ^ (X1 & X3) ^ X2 ^ (X0 & X3) ^ (X0 & X2 & X3) ^ X3 ^ onesMask; // 1 should be 0xFFFFFFFF
	*Y3 = (X1 & X2 & X0) ^ (X1 & X3 & X0) ^ (X0 & X2 & X3) ^ X0 ^ X1 ^ (X1 & X2) ^ X3 ^ onesMask;
}

void sBoxLayer(bs_reg_t *Y, bs_reg_t *X) {
	for (int i = 0; i < 64; i+=4)
	{
		present_sbox(Y + i, Y + (i+1), Y + (i+2), Y + (i+3), X[i], X[i+1], X[i+2], X[i+3]);
	}
	

}

void addRoundKey(bs_reg_t *X, const uint8_t *K) {

	for (int i = 0; i < 64; i++) {
		uint8_t bitOfKey = getbit(K[i/8],i%8);
		if(bitOfKey)
		X[i] ^= onesMask;
	}
}

void pLayer(bs_reg_t *state, bs_reg_t *bb) {
	for(int i = 0; i < 64; i++)
	{
		int new_position_of_the_bit = (i/4) + (i%4) * 16;
		state[new_position_of_the_bit] = bb[i];
	}

}

/**
 * Perform next key schedule step
 * @param key Key register to be updated
 * @param r Round counter
 * @warning For correct function, has to be called with incremented r each time
 * @note You are free to change or optimize this function
 */
static void update_round_key(uint8_t key[CRYPTO_KEY_SIZE], const uint8_t r)
{
	//
	// There is no need to edit this code - but you can do so if you want to
	// optimise further
	//

	const uint8_t sbox[16] = {
		0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2,
	};

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

void crypto_func(uint8_t pt[CRYPTO_IN_SIZE * BITSLICE_WIDTH], uint8_t key[CRYPTO_KEY_SIZE])
{
	// State buffer and additional backbuffer of same size (you can remove the backbuffer if you do not need it)
	bs_reg_t state[CRYPTO_IN_SIZE_BIT];
	bs_reg_t bb[CRYPTO_IN_SIZE_BIT];
	uint8_t round;
	
	for (int i = 0; i < CRYPTO_IN_SIZE_BIT; i++)
	{
		state[i] = 0;
		bb[i] = 0;
	}
	// Bring into bitslicing form
	enslice(pt, state);
	
	// INSERT PRESENT MAIN CODE HERE AND DELETE THIS COMMENT //
	uint8_t i = 0;
	for(i = 1; i <= 31; i++)
	{
		addRoundKey(state, key + 2);
		sBoxLayer(bb, state);
		pLayer(state, bb);
		update_round_key(key, i);
	}

	addRoundKey(state, key + 2);	
	// Convert back to normal form

	for(int i=0;i< 256; ++i){
		pt[i]=0;
	}
	unslice(state, pt);
}