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
	int bitPositionBS = 0;
    int bytePositionHelperBS = 0;
	uint32_t bitValueInBitSlice;
    for (int i = 0; i < CRYPTO_IN_SIZE * BITSLICE_WIDTH; i++) {
		bytePositionHelperBS = i % 8;
        bitValueInBitSlice = 0;
        for (int j = 0; j < 8; j++) {            
            bitValueInBitSlice = getbit(pt[i],7-j) & 0x01;
            state_bs[bytePositionHelperBS * 8 + (7-j)] = state_bs[bytePositionHelperBS * 8 + (7-j)] | (bitValueInBitSlice<<bitPositionBS);
        }
		bitPositionBS += (i+1) % 8 == 0;
    }
}

/**
 * Bring bitsliced buffer into normal form
 * @param state_bs Input: Bitsliced state
 * @param pt Output: state_bs in normal form
 */
static void unslice(const bs_reg_t state_bs[CRYPTO_IN_SIZE_BIT], uint8_t pt[CRYPTO_IN_SIZE * BITSLICE_WIDTH])
{
	uint32_t one=1;
    uint32_t temp[8];
    int bitPosition = 0, result_index=0;
    for(int k=0;k<32;++k){
        for (int i = 0; i < 8; i++) {
            pt[result_index+i];
            bitPosition=0;
            for (int j = 0; j < 8; j++) {
                temp[j]=(one<<k & state_bs[(i*8) + j])>>k;
                pt[result_index+i] = pt[result_index+i] | temp[j]<<bitPosition;
                ++bitPosition;
            }
        }
        result_index+=8; 
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

/**
 * Perform RoundKey Layer in Present Algorithm
 * @param state_bs Input: Bitsliced state
 * @param key Input: Key to perform Add Round Key
 */
void addRoundKey( bs_reg_t *state_bs, const uint8_t *key) {
	state_bs[0] ^= onesMask & (-(key[0] >> 0 & 0x1));
	state_bs[1] ^= onesMask & (-(key[0] >> 1 & 0x1));
	state_bs[2] ^= onesMask & (-(key[0] >> 2 & 0x1));
	state_bs[3] ^= onesMask & (-(key[0] >> 3 & 0x1));
	state_bs[4] ^= onesMask & (-(key[0] >> 4 & 0x1));
	state_bs[5] ^= onesMask & (-(key[0] >> 5 & 0x1));
	state_bs[6] ^= onesMask & (-(key[0] >> 6 & 0x1));
	state_bs[7] ^= onesMask & (-(key[0] >> 7 & 0x1));
	state_bs[8] ^= onesMask & (-(key[1] >> 0 & 0x1));
	state_bs[9] ^= onesMask & (-(key[1] >> 1 & 0x1));
	state_bs[10] ^= onesMask & (-(key[1] >> 2 & 0x1));
	state_bs[11] ^= onesMask & (-(key[1] >> 3 & 0x1));
	state_bs[12] ^= onesMask & (-(key[1] >> 4 & 0x1));
	state_bs[13] ^= onesMask & (-(key[1] >> 5 & 0x1));
	state_bs[14] ^= onesMask & (-(key[1] >> 6 & 0x1));
	state_bs[15] ^= onesMask & (-(key[1] >> 7 & 0x1));
	state_bs[16] ^= onesMask & (-(key[2] >> 0 & 0x1));
	state_bs[17] ^= onesMask & (-(key[2] >> 1 & 0x1));
	state_bs[18] ^= onesMask & (-(key[2] >> 2 & 0x1));
	state_bs[19] ^= onesMask & (-(key[2] >> 3 & 0x1));
	state_bs[20] ^= onesMask & (-(key[2] >> 4 & 0x1));
	state_bs[21] ^= onesMask & (-(key[2] >> 5 & 0x1));
	state_bs[22] ^= onesMask & (-(key[2] >> 6 & 0x1));
	state_bs[23] ^= onesMask & (-(key[2] >> 7 & 0x1));
	state_bs[24] ^= onesMask & (-(key[3] >> 0 & 0x1));
	state_bs[25] ^= onesMask & (-(key[3] >> 1 & 0x1));
	state_bs[26] ^= onesMask & (-(key[3] >> 2 & 0x1));
	state_bs[27] ^= onesMask & (-(key[3] >> 3 & 0x1));
	state_bs[28] ^= onesMask & (-(key[3] >> 4 & 0x1));
	state_bs[29] ^= onesMask & (-(key[3] >> 5 & 0x1));
	state_bs[30] ^= onesMask & (-(key[3] >> 6 & 0x1));
	state_bs[31] ^= onesMask & (-(key[3] >> 7 & 0x1));
	state_bs[32] ^= onesMask & (-(key[4] >> 0 & 0x1));
	state_bs[33] ^= onesMask & (-(key[4] >> 1 & 0x1));
	state_bs[34] ^= onesMask & (-(key[4] >> 2 & 0x1));
	state_bs[35] ^= onesMask & (-(key[4] >> 3 & 0x1));
	state_bs[36] ^= onesMask & (-(key[4] >> 4 & 0x1));
	state_bs[37] ^= onesMask & (-(key[4] >> 5 & 0x1));
	state_bs[38] ^= onesMask & (-(key[4] >> 6 & 0x1));
	state_bs[39] ^= onesMask & (-(key[4] >> 7 & 0x1));
	state_bs[40] ^= onesMask & (-(key[5] >> 0 & 0x1));
	state_bs[41] ^= onesMask & (-(key[5] >> 1 & 0x1));
	state_bs[42] ^= onesMask & (-(key[5] >> 2 & 0x1));
	state_bs[43] ^= onesMask & (-(key[5] >> 3 & 0x1));
	state_bs[44] ^= onesMask & (-(key[5] >> 4 & 0x1));
	state_bs[45] ^= onesMask & (-(key[5] >> 5 & 0x1));
	state_bs[46] ^= onesMask & (-(key[5] >> 6 & 0x1));
	state_bs[47] ^= onesMask & (-(key[5] >> 7 & 0x1));
	state_bs[48] ^= onesMask & (-(key[6] >> 0 & 0x1));
	state_bs[49] ^= onesMask & (-(key[6] >> 1 & 0x1));
	state_bs[50] ^= onesMask & (-(key[6] >> 2 & 0x1));
	state_bs[51] ^= onesMask & (-(key[6] >> 3 & 0x1));
	state_bs[52] ^= onesMask & (-(key[6] >> 4 & 0x1));
	state_bs[53] ^= onesMask & (-(key[6] >> 5 & 0x1));
	state_bs[54] ^= onesMask & (-(key[6] >> 6 & 0x1));
	state_bs[55] ^= onesMask & (-(key[6] >> 7 & 0x1));
	state_bs[56] ^= onesMask & (-(key[7] >> 0 & 0x1));
	state_bs[57] ^= onesMask & (-(key[7] >> 1 & 0x1));
	state_bs[58] ^= onesMask & (-(key[7] >> 2 & 0x1));
	state_bs[59] ^= onesMask & (-(key[7] >> 3 & 0x1));
	state_bs[60] ^= onesMask & (-(key[7] >> 4 & 0x1));
	state_bs[61] ^= onesMask & (-(key[7] >> 5 & 0x1));
	state_bs[62] ^= onesMask & (-(key[7] >> 6 & 0x1));
	state_bs[63] ^= onesMask & (-(key[7] >> 7 & 0x1));
}

/**
 * Perform P-Layer in Present Algorithm
 * @param bb Input: Bitsliced Plain Text after S-Box
 * @param state_bs Output : Bitsliced Plain Text after PLayer
 */
void pLayer(bs_reg_t *state_bs, bs_reg_t *bb ) {
	  state_bs[ 0] = bb[ 0],  state_bs[ 1] = bb[ 4],  state_bs[ 2] = bb[ 8],  state_bs[ 3] = bb[12];
	  state_bs[ 4] = bb[16],  state_bs[ 5] = bb[20],  state_bs[ 6] = bb[24],  state_bs[ 7] = bb[28];
	  state_bs[ 8] = bb[32],  state_bs[ 9] = bb[36],  state_bs[10] = bb[40],  state_bs[11] = bb[44];
	  state_bs[12] = bb[48],  state_bs[13] = bb[52],  state_bs[14] = bb[56],  state_bs[15] = bb[60];
	  state_bs[16] = bb[ 1],  state_bs[17] = bb[ 5],  state_bs[18] = bb[ 9],  state_bs[19] = bb[13];
	  state_bs[20] = bb[17],  state_bs[21] = bb[21],  state_bs[22] = bb[25],  state_bs[23] = bb[29];
	  state_bs[24] = bb[33],  state_bs[25] = bb[37],  state_bs[26] = bb[41],  state_bs[27] = bb[45];
	  state_bs[28] = bb[49],  state_bs[29] = bb[53],  state_bs[30] = bb[57],  state_bs[31] = bb[61];
	  state_bs[32] = bb[ 2],  state_bs[33] = bb[ 6],  state_bs[34] = bb[10],  state_bs[35] = bb[14];
	  state_bs[36] = bb[18],  state_bs[37] = bb[22],  state_bs[38] = bb[26],  state_bs[39] = bb[30];
	  state_bs[40] = bb[34],  state_bs[41] = bb[38],  state_bs[42] = bb[42],  state_bs[43] = bb[46];
	  state_bs[44] = bb[50],  state_bs[45] = bb[54],  state_bs[46] = bb[58],  state_bs[47] = bb[62];
	  state_bs[48] = bb[ 3],  state_bs[49] = bb[ 7],  state_bs[50] = bb[11],  state_bs[51] = bb[15];
	  state_bs[52] = bb[19],  state_bs[53] = bb[23],  state_bs[54] = bb[27],  state_bs[55] = bb[31];
	  state_bs[56] = bb[35],  state_bs[57] = bb[39],  state_bs[58] = bb[43],  state_bs[59] = bb[47];
	  state_bs[60] = bb[51],  state_bs[61] = bb[55],  state_bs[62] = bb[59],  state_bs[63] = bb[63];
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