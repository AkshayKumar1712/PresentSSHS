#include "crypto.h"

static const bs_reg_t onesMask = 0XFFFFFFFF;

static int8_t getbit(uint8_t byte, uint8_t bit)
{
	return byte >> bit & 0x1;
}

/**
 * Bring normal buffer into bitsliced form
 * @param pt Input: state_bs in normal form
 * @param state_bs Output: Bitsliced state
 */
static void enslice(const uint8_t pt[CRYPTO_IN_SIZE * BITSLICE_WIDTH], bs_reg_t state_bs[CRYPTO_IN_SIZE_BIT])
{
	// INSERT YOUR CODE HERE AND DELETE THIS COMMENT
	int k = 0;
    int count=-1;
	uint32_t bitadd;
    
    for (int i = 0; i < CRYPTO_IN_SIZE * BITSLICE_WIDTH; i++) {
        // uint8_t byte = pt[i];
		count = (count+1) % 8;
        bitadd = 0;
        for (int j = 0; j < 8; j++) {
            if(i<8) {
                state_bs[i * 8 + (7-j)] = getbit(pt[i],7-j) & 0x01;
            } else {
                 bitadd = getbit(pt[i],7-j) & 0x01;
                 state_bs[count * 8 + (7-j)] = state_bs[count * 8 + (7-j)] | (bitadd<<k);
            }
        }

		if((i+1)%8==0) {
			k++;
		}
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
	// *Y0 = X0 ^ (X1 & X2) ^ X2 ^ X3;
	// *Y1 = (X0 & X2 & X1) ^ (X0 & X3 & X1) ^ (X1 & X3) ^ X1 ^ (X0 & X2 & X3) ^ (X2 & X3) ^ X3;
	// *Y2 = (X0 & X1) ^ (X0 & X3 & X1) ^ (X1 & X3) ^ X2 ^ (X0 & X3) ^ (X0 & X2 & X3) ^ X3 ^ onesMask; // 1 should be 0xFFFFFFFF
	// *Y3 = (X1 & X2 & X0) ^ (X1 & X3 & X0) ^ (X0 & X2 & X3) ^ X0 ^ X1 ^ (X1 & X2) ^ X3 ^ onesMask;
	register bs_reg_t T1,T2,T3,T4;
	T1 = X1 ^ X2;
	T2 = X2 & T1;
	T3 = X3 ^ T2;
	*Y0 = X0 ^ T3;
	T2 = T1 & T3;
	T1 ^= (*Y0);
	T2 ^= X2;
	T4 = X0 | T2;
	*Y1 = T1 ^ T4;
	T2 ^= (~X0);
	*Y3 = (*Y1) ^ T2;
	T2 |= T1;
	*Y2 = T3 ^ T2;
}

void sBoxLayer(bs_reg_t *sbox_result, bs_reg_t *state_bs) {
	register bs_reg_t T1,T2,T3,T4;
	for (int i = 0; i < 64; i+=4)
	{
		T1 = state_bs[i+1] ^ state_bs[i+2];
		T2 = state_bs[i+2] & T1;
		T3 = state_bs[i+3] ^ T2;
		sbox_result[i] = state_bs[i] ^ T3;
		T2 = T1 & T3;
		T1 ^= (sbox_result[i]);
		T2 ^= state_bs[i+2];
		T4 = state_bs[i] | T2;
		sbox_result[i+1] = T1 ^ T4;
		T2 ^= (~state_bs[i]);
		sbox_result[i+3] = (sbox_result[i+1]) ^ T2;
		T2 |= T1;
		sbox_result[i+2] = T3 ^ T2;
		// present_sbox(sbox_result + i, sbox_result + (i+1), sbox_result + (i+2), sbox_result + (i+3), state_bs[i], state_bs[i+1], state_bs[i+2], state_bs[i+3]);
	}
	
	// present_sbox(Y+ 0,Y+ 1,Y+ 2,Y+ 3, X[ 0],X[ 1],X[ 2],X[ 3]);
	// present_sbox(Y+ 4,Y+ 5,Y+ 6,Y+ 7, X[ 4],X[ 5],X[ 6],X[ 7]);
	// present_sbox(Y+ 8,Y+ 9,Y+10,Y+11, X[ 8],X[ 9],X[10],X[11]);
	// present_sbox(Y+12,Y+13,Y+14,Y+15, X[12],X[13],X[14],X[15]);
	// present_sbox(Y+16,Y+17,Y+18,Y+19, X[16],X[17],X[18],X[19]);

	// present_sbox(Y+20,Y+21,Y+22,Y+23, X[20],X[21],X[22],X[23]);
	// present_sbox(Y+24,Y+25,Y+26,Y+27, X[24],X[25],X[26],X[27]);
	// present_sbox(Y+28,Y+29,Y+30,Y+31, X[28],X[29],X[30],X[31]);
	// present_sbox(Y+32,Y+33,Y+34,Y+35, X[32],X[33],X[34],X[35]);
	// present_sbox(Y+36,Y+37,Y+38,Y+39, X[36],X[37],X[38],X[39]);

	// present_sbox(Y+40,Y+41,Y+42,Y+43, X[40],X[41],X[42],X[43]);
	// present_sbox(Y+44,Y+45,Y+46,Y+47, X[44],X[45],X[46],X[47]);
	// present_sbox(Y+48,Y+49,Y+50,Y+51, X[48],X[49],X[50],X[51]);
	// present_sbox(Y+52,Y+53,Y+54,Y+55, X[52],X[53],X[54],X[55]);
	// present_sbox(Y+56,Y+57,Y+58,Y+59, X[56],X[57],X[58],X[59]);

	// present_sbox(Y+60,Y+61,Y+62,Y+63, X[60],X[61],X[62],X[63]);
}

void addRoundKey(bs_reg_t *state_bs, const uint8_t *key) {

	// for (int i = 0; i < 64; i++) {
	// 	uint8_t bitOfKey = getbit(K[i/8],i%8);
	// 	// if(bitOfKey)
	// 	// {
	// 	// 	X[i] ^= onesMask;
	// 	// }
	// 	X[i] ^= onesMask & (-bitOfKey);
	// }
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

void pLayer(bs_reg_t *X, bs_reg_t *Y) {
	// for(int i = 0; i < 64; i++)
	// {
	// 	int new_position_of_the_bit = (i/4) + (i%4) * 16;
	// 	state[new_position_of_the_bit] = bb[i];
	// }
	  X[ 0] = Y[ 0],  X[ 1] = Y[ 4],  X[ 2] = Y[ 8],  X[ 3] = Y[12];
	  X[ 4] = Y[16],  X[ 5] = Y[20],  X[ 6] = Y[24],  X[ 7] = Y[28];
	  X[ 8] = Y[32],  X[ 9] = Y[36],  X[10] = Y[40],  X[11] = Y[44];
	  X[12] = Y[48],  X[13] = Y[52],  X[14] = Y[56],  X[15] = Y[60];
	  X[16] = Y[ 1],  X[17] = Y[ 5],  X[18] = Y[ 9],  X[19] = Y[13];
	  X[20] = Y[17],  X[21] = Y[21],  X[22] = Y[25],  X[23] = Y[29];
	  X[24] = Y[33],  X[25] = Y[37],  X[26] = Y[41],  X[27] = Y[45];
	  X[28] = Y[49],  X[29] = Y[53],  X[30] = Y[57],  X[31] = Y[61];
	  X[32] = Y[ 2],  X[33] = Y[ 6],  X[34] = Y[10],  X[35] = Y[14];
	  X[36] = Y[18],  X[37] = Y[22],  X[38] = Y[26],  X[39] = Y[30];
	  X[40] = Y[34],  X[41] = Y[38],  X[42] = Y[42],  X[43] = Y[46];
	  X[44] = Y[50],  X[45] = Y[54],  X[46] = Y[58],  X[47] = Y[62];
	  X[48] = Y[ 3],  X[49] = Y[ 7],  X[50] = Y[11],  X[51] = Y[15];
	  X[52] = Y[19],  X[53] = Y[23],  X[54] = Y[27],  X[55] = Y[31];
	  X[56] = Y[35],  X[57] = Y[39],  X[58] = Y[43],  X[59] = Y[47];
	  X[60] = Y[51],  X[61] = Y[55],  X[62] = Y[59],  X[63] = Y[63];
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
	
	// for (int i = 0; i < CRYPTO_IN_SIZE_BIT; i++)
	// {
	// 	state[i] = 0;
	// 	bb[i] = 0;
	// }
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

	memset(pt, 0, 256);

	unslice(state, pt);
}