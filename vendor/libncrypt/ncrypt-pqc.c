// libncrypt-pqc 0.1.0
// Post-quantum extension for libncrypt
//
// The ML-KEM-768 and ML-DSA-44 cores below are carried over from the
// CRYSTALS reference implementations (public domain, by the Kyber and
// Dilithium teams), folded into this single translation unit with all
// internal symbols made static.  The public wrappers at the bottom of
// the file follow libncrypt conventions: no allocation, no internal
// RNG, seeds are wiped after use.
//
// Compile together with ncrypt.c (this file borrows its AEAD, BLAKE2b,
// constant time comparison, and wiping routines).

#include "ncrypt-pqc.h"

#define KYBER_K        3   // ML-KEM-768
#define DILITHIUM_MODE 2   // ML-DSA-44

// ----- fips202.h -----
#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72


typedef struct {
  uint64_t s[25];
  unsigned int pos;
} keccak_state;

static void shake128_init(keccak_state *state);
static void shake128_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
static void shake128_finalize(keccak_state *state);
static void shake128_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen);
static void shake128_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state);

static void shake256_init(keccak_state *state);
static void shake256_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
static void shake256_finalize(keccak_state *state);
static void shake256_squeeze(uint8_t *out, size_t outlen, keccak_state *state);
static void shake256_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen);
static void shake256_squeezeblocks(uint8_t *out, size_t nblocks,  keccak_state *state);

static void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
static void sha3_256(uint8_t h[32], const uint8_t *in, size_t inlen);
static void sha3_512(uint8_t h[64], const uint8_t *in, size_t inlen);

// ----- fips202.c -----
/* Based on the public domain implementation in crypto_hash/keccakc512/simple/ from
 * http://bench.cr.yp.to/supercop.html by Ronny Van Keer and the public domain "TweetFips202"
 * implementation from https://twitter.com/tweetfips202 by Gilles Van Assche, Daniel J. Bernstein,
 * and Peter Schwabe */


#define NROUNDS 24
#define ROL(a, offset) ((a << offset) ^ (a >> (64-offset)))

/*************************************************
* Name:        load64
*
* Description: Load 8 bytes into uint64_t in little-endian order
*
* Arguments:   - const uint8_t *x: pointer to input byte array
*
* Returns the loaded 64-bit unsigned integer
**************************************************/
static uint64_t load64(const uint8_t x[8]) {
  unsigned int i;
  uint64_t r = 0;

  for(i=0;i<8;i++)
    r |= (uint64_t)x[i] << 8*i;

  return r;
}

/*************************************************
* Name:        store64
*
* Description: Store a 64-bit integer to array of 8 bytes in little-endian order
*
* Arguments:   - uint8_t *x: pointer to the output byte array (allocated)
*              - uint64_t u: input 64-bit unsigned integer
**************************************************/
static void store64(uint8_t x[8], uint64_t u) {
  unsigned int i;

  for(i=0;i<8;i++)
    x[i] = u >> 8*i;
}

/* Keccak round constants */
static const uint64_t KeccakF_RoundConstants[NROUNDS] = {
  (uint64_t)0x0000000000000001ULL,
  (uint64_t)0x0000000000008082ULL,
  (uint64_t)0x800000000000808aULL,
  (uint64_t)0x8000000080008000ULL,
  (uint64_t)0x000000000000808bULL,
  (uint64_t)0x0000000080000001ULL,
  (uint64_t)0x8000000080008081ULL,
  (uint64_t)0x8000000000008009ULL,
  (uint64_t)0x000000000000008aULL,
  (uint64_t)0x0000000000000088ULL,
  (uint64_t)0x0000000080008009ULL,
  (uint64_t)0x000000008000000aULL,
  (uint64_t)0x000000008000808bULL,
  (uint64_t)0x800000000000008bULL,
  (uint64_t)0x8000000000008089ULL,
  (uint64_t)0x8000000000008003ULL,
  (uint64_t)0x8000000000008002ULL,
  (uint64_t)0x8000000000000080ULL,
  (uint64_t)0x000000000000800aULL,
  (uint64_t)0x800000008000000aULL,
  (uint64_t)0x8000000080008081ULL,
  (uint64_t)0x8000000000008080ULL,
  (uint64_t)0x0000000080000001ULL,
  (uint64_t)0x8000000080008008ULL
};

/*************************************************
* Name:        KeccakF1600_StatePermute
*
* Description: The Keccak F1600 Permutation
*
* Arguments:   - uint64_t *state: pointer to input/output Keccak state
**************************************************/
static void KeccakF1600_StatePermute(uint64_t state[25])
{
        int round;

        uint64_t Aba, Abe, Abi, Abo, Abu;
        uint64_t Aga, Age, Agi, Ago, Agu;
        uint64_t Aka, Ake, Aki, Ako, Aku;
        uint64_t Ama, Ame, Ami, Amo, Amu;
        uint64_t Asa, Ase, Asi, Aso, Asu;
        uint64_t BCa, BCe, BCi, BCo, BCu;
        uint64_t Da, De, Di, Do, Du;
        uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
        uint64_t Ega, Ege, Egi, Ego, Egu;
        uint64_t Eka, Eke, Eki, Eko, Eku;
        uint64_t Ema, Eme, Emi, Emo, Emu;
        uint64_t Esa, Ese, Esi, Eso, Esu;

        //copyFromState(A, state)
        Aba = state[ 0];
        Abe = state[ 1];
        Abi = state[ 2];
        Abo = state[ 3];
        Abu = state[ 4];
        Aga = state[ 5];
        Age = state[ 6];
        Agi = state[ 7];
        Ago = state[ 8];
        Agu = state[ 9];
        Aka = state[10];
        Ake = state[11];
        Aki = state[12];
        Ako = state[13];
        Aku = state[14];
        Ama = state[15];
        Ame = state[16];
        Ami = state[17];
        Amo = state[18];
        Amu = state[19];
        Asa = state[20];
        Ase = state[21];
        Asi = state[22];
        Aso = state[23];
        Asu = state[24];

        for(round = 0; round < NROUNDS; round += 2) {
            //    prepareTheta
            BCa = Aba^Aga^Aka^Ama^Asa;
            BCe = Abe^Age^Ake^Ame^Ase;
            BCi = Abi^Agi^Aki^Ami^Asi;
            BCo = Abo^Ago^Ako^Amo^Aso;
            BCu = Abu^Agu^Aku^Amu^Asu;

            //thetaRhoPiChiIotaPrepareTheta(round, A, E)
            Da = BCu^ROL(BCe, 1);
            De = BCa^ROL(BCi, 1);
            Di = BCe^ROL(BCo, 1);
            Do = BCi^ROL(BCu, 1);
            Du = BCo^ROL(BCa, 1);

            Aba ^= Da;
            BCa = Aba;
            Age ^= De;
            BCe = ROL(Age, 44);
            Aki ^= Di;
            BCi = ROL(Aki, 43);
            Amo ^= Do;
            BCo = ROL(Amo, 21);
            Asu ^= Du;
            BCu = ROL(Asu, 14);
            Eba =   BCa ^((~BCe)&  BCi );
            Eba ^= (uint64_t)KeccakF_RoundConstants[round];
            Ebe =   BCe ^((~BCi)&  BCo );
            Ebi =   BCi ^((~BCo)&  BCu );
            Ebo =   BCo ^((~BCu)&  BCa );
            Ebu =   BCu ^((~BCa)&  BCe );

            Abo ^= Do;
            BCa = ROL(Abo, 28);
            Agu ^= Du;
            BCe = ROL(Agu, 20);
            Aka ^= Da;
            BCi = ROL(Aka,  3);
            Ame ^= De;
            BCo = ROL(Ame, 45);
            Asi ^= Di;
            BCu = ROL(Asi, 61);
            Ega =   BCa ^((~BCe)&  BCi );
            Ege =   BCe ^((~BCi)&  BCo );
            Egi =   BCi ^((~BCo)&  BCu );
            Ego =   BCo ^((~BCu)&  BCa );
            Egu =   BCu ^((~BCa)&  BCe );

            Abe ^= De;
            BCa = ROL(Abe,  1);
            Agi ^= Di;
            BCe = ROL(Agi,  6);
            Ako ^= Do;
            BCi = ROL(Ako, 25);
            Amu ^= Du;
            BCo = ROL(Amu,  8);
            Asa ^= Da;
            BCu = ROL(Asa, 18);
            Eka =   BCa ^((~BCe)&  BCi );
            Eke =   BCe ^((~BCi)&  BCo );
            Eki =   BCi ^((~BCo)&  BCu );
            Eko =   BCo ^((~BCu)&  BCa );
            Eku =   BCu ^((~BCa)&  BCe );

            Abu ^= Du;
            BCa = ROL(Abu, 27);
            Aga ^= Da;
            BCe = ROL(Aga, 36);
            Ake ^= De;
            BCi = ROL(Ake, 10);
            Ami ^= Di;
            BCo = ROL(Ami, 15);
            Aso ^= Do;
            BCu = ROL(Aso, 56);
            Ema =   BCa ^((~BCe)&  BCi );
            Eme =   BCe ^((~BCi)&  BCo );
            Emi =   BCi ^((~BCo)&  BCu );
            Emo =   BCo ^((~BCu)&  BCa );
            Emu =   BCu ^((~BCa)&  BCe );

            Abi ^= Di;
            BCa = ROL(Abi, 62);
            Ago ^= Do;
            BCe = ROL(Ago, 55);
            Aku ^= Du;
            BCi = ROL(Aku, 39);
            Ama ^= Da;
            BCo = ROL(Ama, 41);
            Ase ^= De;
            BCu = ROL(Ase,  2);
            Esa =   BCa ^((~BCe)&  BCi );
            Ese =   BCe ^((~BCi)&  BCo );
            Esi =   BCi ^((~BCo)&  BCu );
            Eso =   BCo ^((~BCu)&  BCa );
            Esu =   BCu ^((~BCa)&  BCe );

            //    prepareTheta
            BCa = Eba^Ega^Eka^Ema^Esa;
            BCe = Ebe^Ege^Eke^Eme^Ese;
            BCi = Ebi^Egi^Eki^Emi^Esi;
            BCo = Ebo^Ego^Eko^Emo^Eso;
            BCu = Ebu^Egu^Eku^Emu^Esu;

            //thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
            Da = BCu^ROL(BCe, 1);
            De = BCa^ROL(BCi, 1);
            Di = BCe^ROL(BCo, 1);
            Do = BCi^ROL(BCu, 1);
            Du = BCo^ROL(BCa, 1);

            Eba ^= Da;
            BCa = Eba;
            Ege ^= De;
            BCe = ROL(Ege, 44);
            Eki ^= Di;
            BCi = ROL(Eki, 43);
            Emo ^= Do;
            BCo = ROL(Emo, 21);
            Esu ^= Du;
            BCu = ROL(Esu, 14);
            Aba =   BCa ^((~BCe)&  BCi );
            Aba ^= (uint64_t)KeccakF_RoundConstants[round+1];
            Abe =   BCe ^((~BCi)&  BCo );
            Abi =   BCi ^((~BCo)&  BCu );
            Abo =   BCo ^((~BCu)&  BCa );
            Abu =   BCu ^((~BCa)&  BCe );

            Ebo ^= Do;
            BCa = ROL(Ebo, 28);
            Egu ^= Du;
            BCe = ROL(Egu, 20);
            Eka ^= Da;
            BCi = ROL(Eka, 3);
            Eme ^= De;
            BCo = ROL(Eme, 45);
            Esi ^= Di;
            BCu = ROL(Esi, 61);
            Aga =   BCa ^((~BCe)&  BCi );
            Age =   BCe ^((~BCi)&  BCo );
            Agi =   BCi ^((~BCo)&  BCu );
            Ago =   BCo ^((~BCu)&  BCa );
            Agu =   BCu ^((~BCa)&  BCe );

            Ebe ^= De;
            BCa = ROL(Ebe, 1);
            Egi ^= Di;
            BCe = ROL(Egi, 6);
            Eko ^= Do;
            BCi = ROL(Eko, 25);
            Emu ^= Du;
            BCo = ROL(Emu, 8);
            Esa ^= Da;
            BCu = ROL(Esa, 18);
            Aka =   BCa ^((~BCe)&  BCi );
            Ake =   BCe ^((~BCi)&  BCo );
            Aki =   BCi ^((~BCo)&  BCu );
            Ako =   BCo ^((~BCu)&  BCa );
            Aku =   BCu ^((~BCa)&  BCe );

            Ebu ^= Du;
            BCa = ROL(Ebu, 27);
            Ega ^= Da;
            BCe = ROL(Ega, 36);
            Eke ^= De;
            BCi = ROL(Eke, 10);
            Emi ^= Di;
            BCo = ROL(Emi, 15);
            Eso ^= Do;
            BCu = ROL(Eso, 56);
            Ama =   BCa ^((~BCe)&  BCi );
            Ame =   BCe ^((~BCi)&  BCo );
            Ami =   BCi ^((~BCo)&  BCu );
            Amo =   BCo ^((~BCu)&  BCa );
            Amu =   BCu ^((~BCa)&  BCe );

            Ebi ^= Di;
            BCa = ROL(Ebi, 62);
            Ego ^= Do;
            BCe = ROL(Ego, 55);
            Eku ^= Du;
            BCi = ROL(Eku, 39);
            Ema ^= Da;
            BCo = ROL(Ema, 41);
            Ese ^= De;
            BCu = ROL(Ese, 2);
            Asa =   BCa ^((~BCe)&  BCi );
            Ase =   BCe ^((~BCi)&  BCo );
            Asi =   BCi ^((~BCo)&  BCu );
            Aso =   BCo ^((~BCu)&  BCa );
            Asu =   BCu ^((~BCa)&  BCe );
        }

        //copyToState(state, A)
        state[ 0] = Aba;
        state[ 1] = Abe;
        state[ 2] = Abi;
        state[ 3] = Abo;
        state[ 4] = Abu;
        state[ 5] = Aga;
        state[ 6] = Age;
        state[ 7] = Agi;
        state[ 8] = Ago;
        state[ 9] = Agu;
        state[10] = Aka;
        state[11] = Ake;
        state[12] = Aki;
        state[13] = Ako;
        state[14] = Aku;
        state[15] = Ama;
        state[16] = Ame;
        state[17] = Ami;
        state[18] = Amo;
        state[19] = Amu;
        state[20] = Asa;
        state[21] = Ase;
        state[22] = Asi;
        state[23] = Aso;
        state[24] = Asu;
}

/*************************************************
* Name:        keccak_init
*
* Description: Initializes the Keccak state.
*
* Arguments:   - uint64_t *s: pointer to Keccak state
**************************************************/
static void keccak_init(uint64_t s[25])
{
  unsigned int i;
  for(i=0;i<25;i++)
    s[i] = 0;
}

/*************************************************
* Name:        keccak_absorb
*
* Description: Absorb step of Keccak; incremental.
*
* Arguments:   - uint64_t *s: pointer to Keccak state
*              - unsigned int pos: position in current block to be absorbed
*              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
*              - const uint8_t *in: pointer to input to be absorbed into s
*              - size_t inlen: length of input in bytes
*
* Returns new position pos in current block
**************************************************/
static unsigned int keccak_absorb(uint64_t s[25],
                                  unsigned int pos,
                                  unsigned int r,
                                  const uint8_t *in,
                                  size_t inlen)
{
  unsigned int i;

  while(pos+inlen >= r) {
    for(i=pos;i<r;i++)
      s[i/8] ^= (uint64_t)*in++ << 8*(i%8);
    inlen -= r-pos;
    KeccakF1600_StatePermute(s);
    pos = 0;
  }

  for(i=pos;i<pos+inlen;i++)
    s[i/8] ^= (uint64_t)*in++ << 8*(i%8);

  return i;
}

/*************************************************
* Name:        keccak_finalize
*
* Description: Finalize absorb step.
*
* Arguments:   - uint64_t *s: pointer to Keccak state
*              - unsigned int pos: position in current block to be absorbed
*              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
*              - uint8_t p: domain separation byte
**************************************************/
static void keccak_finalize(uint64_t s[25], unsigned int pos, unsigned int r, uint8_t p)
{
  s[pos/8] ^= (uint64_t)p << 8*(pos%8);
  s[r/8-1] ^= 1ULL << 63;
}

/*************************************************
* Name:        keccak_squeeze
*
* Description: Squeeze step of Keccak. Squeezes arbitratrily many bytes.
*              Modifies the state. Can be called multiple times to keep
*              squeezing, i.e., is incremental.
*
* Arguments:   - uint8_t *out: pointer to output
*              - size_t outlen: number of bytes to be squeezed (written to out)
*              - uint64_t *s: pointer to input/output Keccak state
*              - unsigned int pos: number of bytes in current block already squeezed
*              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
*
* Returns new position pos in current block
**************************************************/
static unsigned int keccak_squeeze(uint8_t *out,
                                   size_t outlen,
                                   uint64_t s[25],
                                   unsigned int pos,
                                   unsigned int r)
{
  unsigned int i;

  while(outlen) {
    if(pos == r) {
      KeccakF1600_StatePermute(s);
      pos = 0;
    }
    for(i=pos;i < r && i < pos+outlen; i++)
      *out++ = s[i/8] >> 8*(i%8);
    outlen -= i-pos;
    pos = i;
  }

  return pos;
}


/*************************************************
* Name:        keccak_absorb_once
*
* Description: Absorb step of Keccak;
*              non-incremental, starts by zeroeing the state.
*
* Arguments:   - uint64_t *s: pointer to (uninitialized) output Keccak state
*              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
*              - const uint8_t *in: pointer to input to be absorbed into s
*              - size_t inlen: length of input in bytes
*              - uint8_t p: domain-separation byte for different Keccak-derived functions
**************************************************/
static void keccak_absorb_once(uint64_t s[25],
                               unsigned int r,
                               const uint8_t *in,
                               size_t inlen,
                               uint8_t p)
{
  unsigned int i;

  for(i=0;i<25;i++)
    s[i] = 0;

  while(inlen >= r) {
    for(i=0;i<r/8;i++)
      s[i] ^= load64(in+8*i);
    in += r;
    inlen -= r;
    KeccakF1600_StatePermute(s);
  }

  for(i=0;i<inlen;i++)
    s[i/8] ^= (uint64_t)in[i] << 8*(i%8);

  s[i/8] ^= (uint64_t)p << 8*(i%8);
  s[(r-1)/8] ^= 1ULL << 63;
}

/*************************************************
* Name:        keccak_squeezeblocks
*
* Description: Squeeze step of Keccak. Squeezes full blocks of r bytes each.
*              Modifies the state. Can be called multiple times to keep
*              squeezing, i.e., is incremental. Assumes zero bytes of current
*              block have already been squeezed.
*
* Arguments:   - uint8_t *out: pointer to output blocks
*              - size_t nblocks: number of blocks to be squeezed (written to out)
*              - uint64_t *s: pointer to input/output Keccak state
*              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
**************************************************/
static void keccak_squeezeblocks(uint8_t *out,
                                 size_t nblocks,
                                 uint64_t s[25],
                                 unsigned int r)
{
  unsigned int i;

  while(nblocks) {
    KeccakF1600_StatePermute(s);
    for(i=0;i<r/8;i++)
      store64(out+8*i, s[i]);
    out += r;
    nblocks -= 1;
  }
}

/*************************************************
* Name:        shake128_init
*
* Description: Initilizes Keccak state for use as SHAKE128 XOF
*
* Arguments:   - keccak_state *state: pointer to (uninitialized) Keccak state
**************************************************/
static void shake128_init(keccak_state *state)
{
  keccak_init(state->s);
  state->pos = 0;
}

/*************************************************
* Name:        shake128_absorb
*
* Description: Absorb step of the SHAKE128 XOF; incremental.
*
* Arguments:   - keccak_state *state: pointer to (initialized) output Keccak state
*              - const uint8_t *in: pointer to input to be absorbed into s
*              - size_t inlen: length of input in bytes
**************************************************/
static void shake128_absorb(keccak_state *state, const uint8_t *in, size_t inlen)
{
  state->pos = keccak_absorb(state->s, state->pos, SHAKE128_RATE, in, inlen);
}

/*************************************************
* Name:        shake128_finalize
*
* Description: Finalize absorb step of the SHAKE128 XOF.
*
* Arguments:   - keccak_state *state: pointer to Keccak state
**************************************************/
static void shake128_finalize(keccak_state *state)
{
  keccak_finalize(state->s, state->pos, SHAKE128_RATE, 0x1F);
  state->pos = SHAKE128_RATE;
}


/*************************************************
* Name:        shake128_absorb_once
*
* Description: Initialize, absorb into and finalize SHAKE128 XOF; non-incremental.
*
* Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak state
*              - const uint8_t *in: pointer to input to be absorbed into s
*              - size_t inlen: length of input in bytes
**************************************************/
static void shake128_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen)
{
  keccak_absorb_once(state->s, SHAKE128_RATE, in, inlen, 0x1F);
  state->pos = SHAKE128_RATE;
}

/*************************************************
* Name:        shake128_squeezeblocks
*
* Description: Squeeze step of SHAKE128 XOF. Squeezes full blocks of
*              SHAKE128_RATE bytes each. Can be called multiple times
*              to keep squeezing. Assumes new block has not yet been
*              started (state->pos = SHAKE128_RATE).
*
* Arguments:   - uint8_t *out: pointer to output blocks
*              - size_t nblocks: number of blocks to be squeezed (written to output)
*              - keccak_state *s: pointer to input/output Keccak state
**************************************************/
static void shake128_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state)
{
  keccak_squeezeblocks(out, nblocks, state->s, SHAKE128_RATE);
}

/*************************************************
* Name:        shake256_init
*
* Description: Initilizes Keccak state for use as SHAKE256 XOF
*
* Arguments:   - keccak_state *state: pointer to (uninitialized) Keccak state
**************************************************/
static void shake256_init(keccak_state *state)
{
  keccak_init(state->s);
  state->pos = 0;
}

/*************************************************
* Name:        shake256_absorb
*
* Description: Absorb step of the SHAKE256 XOF; incremental.
*
* Arguments:   - keccak_state *state: pointer to (initialized) output Keccak state
*              - const uint8_t *in: pointer to input to be absorbed into s
*              - size_t inlen: length of input in bytes
**************************************************/
static void shake256_absorb(keccak_state *state, const uint8_t *in, size_t inlen)
{
  state->pos = keccak_absorb(state->s, state->pos, SHAKE256_RATE, in, inlen);
}

/*************************************************
* Name:        shake256_finalize
*
* Description: Finalize absorb step of the SHAKE256 XOF.
*
* Arguments:   - keccak_state *state: pointer to Keccak state
**************************************************/
static void shake256_finalize(keccak_state *state)
{
  keccak_finalize(state->s, state->pos, SHAKE256_RATE, 0x1F);
  state->pos = SHAKE256_RATE;
}

/*************************************************
* Name:        shake256_squeeze
*
* Description: Squeeze step of SHAKE256 XOF. Squeezes arbitraily many
*              bytes. Can be called multiple times to keep squeezing.
*
* Arguments:   - uint8_t *out: pointer to output blocks
*              - size_t outlen : number of bytes to be squeezed (written to output)
*              - keccak_state *s: pointer to input/output Keccak state
**************************************************/
static void shake256_squeeze(uint8_t *out, size_t outlen, keccak_state *state)
{
  state->pos = keccak_squeeze(out, outlen, state->s, state->pos, SHAKE256_RATE);
}

/*************************************************
* Name:        shake256_absorb_once
*
* Description: Initialize, absorb into and finalize SHAKE256 XOF; non-incremental.
*
* Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak state
*              - const uint8_t *in: pointer to input to be absorbed into s
*              - size_t inlen: length of input in bytes
**************************************************/
static void shake256_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen)
{
  keccak_absorb_once(state->s, SHAKE256_RATE, in, inlen, 0x1F);
  state->pos = SHAKE256_RATE;
}

/*************************************************
* Name:        shake256_squeezeblocks
*
* Description: Squeeze step of SHAKE256 XOF. Squeezes full blocks of
*              SHAKE256_RATE bytes each. Can be called multiple times
*              to keep squeezing. Assumes next block has not yet been
*              started (state->pos = SHAKE256_RATE).
*
* Arguments:   - uint8_t *out: pointer to output blocks
*              - size_t nblocks: number of blocks to be squeezed (written to output)
*              - keccak_state *s: pointer to input/output Keccak state
**************************************************/
static void shake256_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state)
{
  keccak_squeezeblocks(out, nblocks, state->s, SHAKE256_RATE);
}


/*************************************************
* Name:        shake256
*
* Description: SHAKE256 XOF with non-incremental API
*
* Arguments:   - uint8_t *out: pointer to output
*              - size_t outlen: requested output length in bytes
*              - const uint8_t *in: pointer to input
*              - size_t inlen: length of input in bytes
**************************************************/
static void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
  size_t nblocks;
  keccak_state state;

  shake256_absorb_once(&state, in, inlen);
  nblocks = outlen/SHAKE256_RATE;
  shake256_squeezeblocks(out, nblocks, &state);
  outlen -= nblocks*SHAKE256_RATE;
  out += nblocks*SHAKE256_RATE;
  shake256_squeeze(out, outlen, &state);
}

/*************************************************
* Name:        sha3_256
*
* Description: SHA3-256 with non-incremental API
*
* Arguments:   - uint8_t *h: pointer to output (32 bytes)
*              - const uint8_t *in: pointer to input
*              - size_t inlen: length of input in bytes
**************************************************/
static void sha3_256(uint8_t h[32], const uint8_t *in, size_t inlen)
{
  unsigned int i;
  uint64_t s[25];

  keccak_absorb_once(s, SHA3_256_RATE, in, inlen, 0x06);
  KeccakF1600_StatePermute(s);
  for(i=0;i<4;i++)
    store64(h+8*i,s[i]);
}

/*************************************************
* Name:        sha3_512
*
* Description: SHA3-512 with non-incremental API
*
* Arguments:   - uint8_t *h: pointer to output (64 bytes)
*              - const uint8_t *in: pointer to input
*              - size_t inlen: length of input in bytes
**************************************************/
static void sha3_512(uint8_t h[64], const uint8_t *in, size_t inlen)
{
  unsigned int i;
  uint64_t s[25];

  keccak_absorb_once(s, SHA3_512_RATE, in, inlen, 0x06);
  KeccakF1600_StatePermute(s);
  for(i=0;i<8;i++)
    store64(h+8*i,s[i]);
}

// ----- mlkem/params.h -----
#ifndef KYBER_K
#define KYBER_K 3	/* Change this for different security strengths */
#endif


/* Don't change parameters below this line */
#if   (KYBER_K == 2)
#elif (KYBER_K == 3)
#elif (KYBER_K == 4)
#else
#error "KYBER_K must be in {2,3,4}"
#endif

#define KYBER_N 256
#define KYBER_Q 3329

#define KYBER_SYMBYTES 32   /* size in bytes of hashes, and seeds */
#define KYBER_SSBYTES  32   /* size in bytes of shared key */

#define KYBER_POLYBYTES		384
#define KYBER_POLYVECBYTES	(KYBER_K * KYBER_POLYBYTES)

#if KYBER_K == 2
#define KYBER_ETA1 3
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_K == 3
#define KYBER_ETA1 2
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_K == 4
#define KYBER_ETA1 2
#define KYBER_POLYCOMPRESSEDBYTES    160
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 352)
#endif

#define KYBER_ETA2 2

#define KYBER_INDCPA_MSGBYTES       (KYBER_SYMBYTES)
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECBYTES + KYBER_SYMBYTES)
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)
#define KYBER_INDCPA_BYTES          (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)

#define KYBER_PUBLICKEYBYTES  (KYBER_INDCPA_PUBLICKEYBYTES)
/* 32 bytes of additional space to save H(pk) */
#define KYBER_SECRETKEYBYTES  (KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 2*KYBER_SYMBYTES)
#define KYBER_CIPHERTEXTBYTES (KYBER_INDCPA_BYTES)

// ----- mlkem/reduce.h -----
#define MLKEM_MONT -1044 // 2^16 mod q
#define MLKEM_QINV -3327 // q^-1 mod 2^16

static int16_t mlkem_montgomery_reduce(int32_t a);

static int16_t mlkem_barrett_reduce(int16_t a);

// ----- mlkem/ntt.h -----

static void mlkem_ntt(int16_t mlkem_poly[256]);

static void mlkem_invntt(int16_t mlkem_poly[256]);

static void mlkem_basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);

// ----- mlkem/poly.h -----
/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*coeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
typedef struct{
  int16_t coeffs[KYBER_N];
} mlkem_poly;

static void mlkem_poly_compress(uint8_t r[KYBER_POLYCOMPRESSEDBYTES], const mlkem_poly *a);
static void mlkem_poly_decompress(mlkem_poly *r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES]);

static void mlkem_poly_tobytes(uint8_t r[KYBER_POLYBYTES], const mlkem_poly *a);
static void mlkem_poly_frombytes(mlkem_poly *r, const uint8_t a[KYBER_POLYBYTES]);

static void mlkem_poly_frommsg(mlkem_poly *r, const uint8_t msg[KYBER_INDCPA_MSGBYTES]);
static void mlkem_poly_tomsg(uint8_t msg[KYBER_INDCPA_MSGBYTES], const mlkem_poly *r);

static void mlkem_poly_getnoise_eta1(mlkem_poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);

static void mlkem_poly_getnoise_eta2(mlkem_poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);

static void mlkem_poly_ntt(mlkem_poly *r);
static void mlkem_poly_invntt_tomont(mlkem_poly *r);
static void mlkem_poly_basemul_montgomery(mlkem_poly *r, const mlkem_poly *a, const mlkem_poly *b);
static void mlkem_poly_tomont(mlkem_poly *r);

static void mlkem_poly_reduce(mlkem_poly *r);

static void mlkem_poly_add(mlkem_poly *r, const mlkem_poly *a, const mlkem_poly *b);
static void mlkem_poly_sub(mlkem_poly *r, const mlkem_poly *a, const mlkem_poly *b);

// ----- mlkem/cbd.h -----
static void mlkem_poly_cbd_eta1(mlkem_poly *r, const uint8_t buf[KYBER_ETA1*KYBER_N/4]);

static void mlkem_poly_cbd_eta2(mlkem_poly *r, const uint8_t buf[KYBER_ETA2*KYBER_N/4]);

// ----- mlkem/polyvec.h -----
typedef struct{
  mlkem_poly vec[KYBER_K];
} mlkem_polyvec;

static void mlkem_polyvec_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES], const mlkem_polyvec *a);
static void mlkem_polyvec_decompress(mlkem_polyvec *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES]);

static void mlkem_polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], const mlkem_polyvec *a);
static void mlkem_polyvec_frombytes(mlkem_polyvec *r, const uint8_t a[KYBER_POLYVECBYTES]);

static void mlkem_polyvec_ntt(mlkem_polyvec *r);
static void mlkem_polyvec_invntt_tomont(mlkem_polyvec *r);

static void mlkem_polyvec_basemul_acc_montgomery(mlkem_poly *r, const mlkem_polyvec *a, const mlkem_polyvec *b);

static void mlkem_polyvec_reduce(mlkem_polyvec *r);

static void mlkem_polyvec_add(mlkem_polyvec *r, const mlkem_polyvec *a, const mlkem_polyvec *b);

// ----- mlkem/verify.h -----
static int mlkem_verify(const uint8_t *a, const uint8_t *b, size_t len);

static void mlkem_cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b);

static void mlkem_cmov_int16(int16_t *r, int16_t v, uint16_t b);

// ----- mlkem/symmetric.h -----
typedef keccak_state mlkem_xof_state;

static void mlkem_shake128_absorb(keccak_state *s,
                           const uint8_t seed[KYBER_SYMBYTES],
                           uint8_t x,
                           uint8_t y);

static void mlkem_shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce);

static void mlkem_shake256_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES]);

#define XOF_BLOCKBYTES SHAKE128_RATE

#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) mlkem_shake128_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) mlkem_shake256_prf(OUT, OUTBYTES, KEY, NONCE)
#define rkprf(OUT, KEY, INPUT) mlkem_shake256_rkprf(OUT, KEY, INPUT)

// ----- mlkem/indcpa.h -----
static void mlkem_gen_matrix(mlkem_polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed);

static void mlkem_indcpa_keypair_derand(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                           uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
                           const uint8_t coins[KYBER_SYMBYTES]);

static void mlkem_indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES]);

static void mlkem_indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]);

// ----- mlkem/kem.h -----
#define MLKEM_CRYPTO_SECRETKEYBYTES  KYBER_SECRETKEYBYTES
#define MLKEM_CRYPTO_PUBLICKEYBYTES  KYBER_PUBLICKEYBYTES
#define MLKEM_CRYPTO_CIPHERTEXTBYTES KYBER_CIPHERTEXTBYTES
#define MLKEM_CRYPTO_BYTES           KYBER_SSBYTES

#if   (KYBER_K == 2)
#define MLKEM_CRYPTO_ALGNAME "Kyber512"
#elif (KYBER_K == 3)
#define MLKEM_CRYPTO_ALGNAME "Kyber768"
#elif (KYBER_K == 4)
#define MLKEM_CRYPTO_ALGNAME "Kyber1024"
#endif

static int mlkem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);


static int mlkem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);


static int mlkem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

// ----- mlkem/reduce.c -----
/*************************************************
* Name:        mlkem_montgomery_reduce
*
* Description: Montgomery reduction; given a 32-bit integer a, computes
*              16-bit integer congruent to a * R^-1 mod q, where R=2^16
*
* Arguments:   - int32_t a: input integer to be reduced;
*                           has to be in {-q2^15,...,q2^15-1}
*
* Returns:     integer in {-q+1,...,q-1} congruent to a * R^-1 modulo q.
**************************************************/
static int16_t mlkem_montgomery_reduce(int32_t a)
{
  int16_t t;

  t = (int16_t)a*MLKEM_QINV;
  t = (a - (int32_t)t*KYBER_Q) >> 16;
  return t;
}

/*************************************************
* Name:        mlkem_barrett_reduce
*
* Description: Barrett reduction; given a 16-bit integer a, computes
*              centered representative congruent to a mod q in {-(q-1)/2,...,(q-1)/2}
*
* Arguments:   - int16_t a: input integer to be reduced
*
* Returns:     integer in {-(q-1)/2,...,(q-1)/2} congruent to a modulo q.
**************************************************/
static int16_t mlkem_barrett_reduce(int16_t a) {
  int16_t t;
  const int16_t v = ((1<<26) + KYBER_Q/2)/KYBER_Q;

  t  = ((int32_t)v*a + (1<<25)) >> 26;
  t *= KYBER_Q;
  return a - t;
}

// ----- mlkem/ntt.c -----
/* Code to generate mlkem_zetas and zetas_inv used in the number-theoretic transform:

#define KYBER_ROOT_OF_UNITY 17

static const uint8_t tree[128] = {
  0, 64, 32, 96, 16, 80, 48, 112, 8, 72, 40, 104, 24, 88, 56, 120,
  4, 68, 36, 100, 20, 84, 52, 116, 12, 76, 44, 108, 28, 92, 60, 124,
  2, 66, 34, 98, 18, 82, 50, 114, 10, 74, 42, 106, 26, 90, 58, 122,
  6, 70, 38, 102, 22, 86, 54, 118, 14, 78, 46, 110, 30, 94, 62, 126,
  1, 65, 33, 97, 17, 81, 49, 113, 9, 73, 41, 105, 25, 89, 57, 121,
  5, 69, 37, 101, 21, 85, 53, 117, 13, 77, 45, 109, 29, 93, 61, 125,
  3, 67, 35, 99, 19, 83, 51, 115, 11, 75, 43, 107, 27, 91, 59, 123,
  7, 71, 39, 103, 23, 87, 55, 119, 15, 79, 47, 111, 31, 95, 63, 127
};

static void init_ntt() {
  unsigned int i;
  int16_t tmp[128];

  tmp[0] = MLKEM_MONT;
  for(i=1;i<128;i++)
    tmp[i] = fqmul(tmp[i-1],MLKEM_MONT*KYBER_ROOT_OF_UNITY % KYBER_Q);

  for(i=0;i<128;i++) {
    mlkem_zetas[i] = tmp[tree[i]];
    if(mlkem_zetas[i] > KYBER_Q/2)
      mlkem_zetas[i] -= KYBER_Q;
    if(mlkem_zetas[i] < -KYBER_Q/2)
      mlkem_zetas[i] += KYBER_Q;
  }
}
*/

static const int16_t mlkem_zetas[128] = {
  -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
   -171,   622,  1577,   182,   962, -1202, -1474,  1468,
    573, -1325,   264,   383,  -829,  1458, -1602,  -130,
   -681,  1017,   732,   608, -1542,   411,  -205, -1571,
   1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
    516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
   -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
   -398,   961, -1508,  -725,   448, -1065,   677, -1275,
  -1103,   430,   555,   843, -1251,   871,  1550,   105,
    422,   587,   177,  -235,  -291,  -460,  1574,  1653,
   -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
  -1590,   644,  -872,   349,   418,   329,  -156,   -75,
    817,  1097,   603,   610,  1322, -1285, -1465,   384,
  -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
  -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
   -108,  -308,   996,   991,   958, -1460,  1522,  1628
};

/*************************************************
* Name:        fqmul
*
* Description: Multiplication followed by Montgomery reduction
*
* Arguments:   - int16_t a: first factor
*              - int16_t b: second factor
*
* Returns 16-bit integer congruent to a*b*R^{-1} mod q
**************************************************/
static int16_t fqmul(int16_t a, int16_t b) {
  return mlkem_montgomery_reduce((int32_t)a*b);
}

/*************************************************
* Name:        mlkem_ntt
*
* Description: Inplace number-theoretic transform (NTT) in Rq.
*              input is in standard order, output is in bitreversed order
*
* Arguments:   - int16_t r[256]: pointer to input/output vector of elements of Zq
**************************************************/
static void mlkem_ntt(int16_t r[256]) {
  unsigned int len, start, j, k;
  int16_t t, zeta;

  k = 1;
  for(len = 128; len >= 2; len >>= 1) {
    for(start = 0; start < 256; start = j + len) {
      zeta = mlkem_zetas[k++];
      for(j = start; j < start + len; j++) {
        t = fqmul(zeta, r[j + len]);
        r[j + len] = r[j] - t;
        r[j] = r[j] + t;
      }
    }
  }
}

/*************************************************
* Name:        invntt_tomont
*
* Description: Inplace inverse number-theoretic transform in Rq and
*              multiplication by Montgomery factor 2^16.
*              Input is in bitreversed order, output is in standard order
*
* Arguments:   - int16_t r[256]: pointer to input/output vector of elements of Zq
**************************************************/
static void mlkem_invntt(int16_t r[256]) {
  unsigned int start, len, j, k;
  int16_t t, zeta;
  const int16_t f = 1441; // mont^2/128

  k = 127;
  for(len = 2; len <= 128; len <<= 1) {
    for(start = 0; start < 256; start = j + len) {
      zeta = mlkem_zetas[k--];
      for(j = start; j < start + len; j++) {
        t = r[j];
        r[j] = mlkem_barrett_reduce(t + r[j + len]);
        r[j + len] = r[j + len] - t;
        r[j + len] = fqmul(zeta, r[j + len]);
      }
    }
  }

  for(j = 0; j < 256; j++)
    r[j] = fqmul(r[j], f);
}

/*************************************************
* Name:        mlkem_basemul
*
* Description: Multiplication of polynomials in Zq[X]/(X^2-zeta)
*              used for multiplication of elements in Rq in NTT domain
*
* Arguments:   - int16_t r[2]: pointer to the output polynomial
*              - const int16_t a[2]: pointer to the first factor
*              - const int16_t b[2]: pointer to the second factor
*              - int16_t zeta: integer defining the reduction polynomial
**************************************************/
static void mlkem_basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta)
{
  r[0]  = fqmul(a[1], b[1]);
  r[0]  = fqmul(r[0], zeta);
  r[0] += fqmul(a[0], b[0]);
  r[1]  = fqmul(a[0], b[1]);
  r[1] += fqmul(a[1], b[0]);
}

// ----- mlkem/cbd.c -----
/*************************************************
* Name:        load32_littleendian
*
* Description: load 4 bytes into a 32-bit integer
*              in little-endian order
*
* Arguments:   - const uint8_t *x: pointer to input byte array
*
* Returns 32-bit unsigned integer loaded from x
**************************************************/
static uint32_t load32_littleendian(const uint8_t x[4])
{
  uint32_t r;
  r  = (uint32_t)x[0];
  r |= (uint32_t)x[1] << 8;
  r |= (uint32_t)x[2] << 16;
  r |= (uint32_t)x[3] << 24;
  return r;
}

/*************************************************
* Name:        load24_littleendian
*
* Description: load 3 bytes into a 32-bit integer
*              in little-endian order.
*              This function is only needed for Kyber-512
*
* Arguments:   - const uint8_t *x: pointer to input byte array
*
* Returns 32-bit unsigned integer loaded from x (most significant byte is zero)
**************************************************/
#if KYBER_ETA1 == 3
static uint32_t load24_littleendian(const uint8_t x[3])
{
  uint32_t r;
  r  = (uint32_t)x[0];
  r |= (uint32_t)x[1] << 8;
  r |= (uint32_t)x[2] << 16;
  return r;
}
#endif


/*************************************************
* Name:        cbd2
*
* Description: Given an array of uniformly random bytes, compute
*              polynomial with coefficients distributed according to
*              a centered binomial distribution with parameter eta=2
*
* Arguments:   - mlkem_poly *r: pointer to output polynomial
*              - const uint8_t *buf: pointer to input byte array
**************************************************/
static void cbd2(mlkem_poly *r, const uint8_t buf[2*KYBER_N/4])
{
  unsigned int i,j;
  uint32_t t,d;
  int16_t a,b;

  for(i=0;i<KYBER_N/8;i++) {
    t  = load32_littleendian(buf+4*i);
    d  = t & 0x55555555;
    d += (t>>1) & 0x55555555;

    for(j=0;j<8;j++) {
      a = (d >> (4*j+0)) & 0x3;
      b = (d >> (4*j+2)) & 0x3;
      r->coeffs[8*i+j] = a - b;
    }
  }
}

/*************************************************
* Name:        cbd3
*
* Description: Given an array of uniformly random bytes, compute
*              polynomial with coefficients distributed according to
*              a centered binomial distribution with parameter eta=3.
*              This function is only needed for Kyber-512
*
* Arguments:   - mlkem_poly *r: pointer to output polynomial
*              - const uint8_t *buf: pointer to input byte array
**************************************************/
#if KYBER_ETA1 == 3
static void cbd3(mlkem_poly *r, const uint8_t buf[3*KYBER_N/4])
{
  unsigned int i,j;
  uint32_t t,d;
  int16_t a,b;

  for(i=0;i<KYBER_N/4;i++) {
    t  = load24_littleendian(buf+3*i);
    d  = t & 0x00249249;
    d += (t>>1) & 0x00249249;
    d += (t>>2) & 0x00249249;

    for(j=0;j<4;j++) {
      a = (d >> (6*j+0)) & 0x7;
      b = (d >> (6*j+3)) & 0x7;
      r->coeffs[4*i+j] = a - b;
    }
  }
}
#endif

static void mlkem_poly_cbd_eta1(mlkem_poly *r, const uint8_t buf[KYBER_ETA1*KYBER_N/4])
{
#if KYBER_ETA1 == 2
  cbd2(r, buf);
#elif KYBER_ETA1 == 3
  cbd3(r, buf);
#else
#error "This implementation requires eta1 in {2,3}"
#endif
}

static void mlkem_poly_cbd_eta2(mlkem_poly *r, const uint8_t buf[KYBER_ETA2*KYBER_N/4])
{
#if KYBER_ETA2 == 2
  cbd2(r, buf);
#else
#error "This implementation requires eta2 = 2"
#endif
}

// ----- mlkem/poly.c -----
/*************************************************
* Name:        mlkem_poly_compress
*
* Description: Compression and subsequent serialization of a polynomial
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (of length KYBER_POLYCOMPRESSEDBYTES)
*              - const mlkem_poly *a: pointer to input polynomial
**************************************************/
static void mlkem_poly_compress(uint8_t r[KYBER_POLYCOMPRESSEDBYTES], const mlkem_poly *a)
{
  unsigned int i,j;
  int32_t u;
  uint32_t d0;
  uint8_t t[8];

#if (KYBER_POLYCOMPRESSEDBYTES == 128)

  for(i=0;i<KYBER_N/8;i++) {
    for(j=0;j<8;j++) {
      // map to positive standard representatives
      u  = a->coeffs[8*i+j];
      u += (u >> 15) & KYBER_Q;
/*    t[j] = ((((uint16_t)u << 4) + KYBER_Q/2)/KYBER_Q) & 15; */
      d0 = u << 4;
      d0 += 1665;
      d0 *= 80635;
      d0 >>= 28;
      t[j] = d0 & 0xf;
    }

    r[0] = t[0] | (t[1] << 4);
    r[1] = t[2] | (t[3] << 4);
    r[2] = t[4] | (t[5] << 4);
    r[3] = t[6] | (t[7] << 4);
    r += 4;
  }
#elif (KYBER_POLYCOMPRESSEDBYTES == 160)
  for(i=0;i<KYBER_N/8;i++) {
    for(j=0;j<8;j++) {
      // map to positive standard representatives
      u  = a->coeffs[8*i+j];
      u += (u >> 15) & KYBER_Q;
/*    t[j] = ((((uint32_t)u << 5) + KYBER_Q/2)/KYBER_Q) & 31; */
      d0 = u << 5;
      d0 += 1664;
      d0 *= 40318;
      d0 >>= 27;
      t[j] = d0 & 0x1f;
    }

    r[0] = (t[0] >> 0) | (t[1] << 5);
    r[1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
    r[2] = (t[3] >> 1) | (t[4] << 4);
    r[3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
    r[4] = (t[6] >> 2) | (t[7] << 3);
    r += 5;
  }
#else
#error "KYBER_POLYCOMPRESSEDBYTES needs to be in {128, 160}"
#endif
}

/*************************************************
* Name:        mlkem_poly_decompress
*
* Description: De-serialization and subsequent decompression of a polynomial;
*              approximate inverse of mlkem_poly_compress
*
* Arguments:   - mlkem_poly *r: pointer to output polynomial
*              - const uint8_t *a: pointer to input byte array
*                                  (of length KYBER_POLYCOMPRESSEDBYTES bytes)
**************************************************/
static void mlkem_poly_decompress(mlkem_poly *r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES])
{
  unsigned int i;

#if (KYBER_POLYCOMPRESSEDBYTES == 128)
  for(i=0;i<KYBER_N/2;i++) {
    r->coeffs[2*i+0] = (((uint16_t)(a[0] & 15)*KYBER_Q) + 8) >> 4;
    r->coeffs[2*i+1] = (((uint16_t)(a[0] >> 4)*KYBER_Q) + 8) >> 4;
    a += 1;
  }
#elif (KYBER_POLYCOMPRESSEDBYTES == 160)
  unsigned int j;
  uint8_t t[8];
  for(i=0;i<KYBER_N/8;i++) {
    t[0] = (a[0] >> 0);
    t[1] = (a[0] >> 5) | (a[1] << 3);
    t[2] = (a[1] >> 2);
    t[3] = (a[1] >> 7) | (a[2] << 1);
    t[4] = (a[2] >> 4) | (a[3] << 4);
    t[5] = (a[3] >> 1);
    t[6] = (a[3] >> 6) | (a[4] << 2);
    t[7] = (a[4] >> 3);
    a += 5;

    for(j=0;j<8;j++)
      r->coeffs[8*i+j] = ((uint32_t)(t[j] & 31)*KYBER_Q + 16) >> 5;
  }
#else
#error "KYBER_POLYCOMPRESSEDBYTES needs to be in {128, 160}"
#endif
}

/*************************************************
* Name:        mlkem_poly_tobytes
*
* Description: Serialization of a polynomial
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (needs space for KYBER_POLYBYTES bytes)
*              - const mlkem_poly *a: pointer to input polynomial
**************************************************/
static void mlkem_poly_tobytes(uint8_t r[KYBER_POLYBYTES], const mlkem_poly *a)
{
  unsigned int i;
  uint16_t t0, t1;

  for(i=0;i<KYBER_N/2;i++) {
    // map to positive standard representatives
    t0  = a->coeffs[2*i];
    t0 += ((int16_t)t0 >> 15) & KYBER_Q;
    t1 = a->coeffs[2*i+1];
    t1 += ((int16_t)t1 >> 15) & KYBER_Q;
    r[3*i+0] = (t0 >> 0);
    r[3*i+1] = (t0 >> 8) | (t1 << 4);
    r[3*i+2] = (t1 >> 4);
  }
}

/*************************************************
* Name:        mlkem_poly_frombytes
*
* Description: De-serialization of a polynomial;
*              inverse of mlkem_poly_tobytes
*
* Arguments:   - mlkem_poly *r: pointer to output polynomial
*              - const uint8_t *a: pointer to input byte array
*                                  (of KYBER_POLYBYTES bytes)
**************************************************/
static void mlkem_poly_frombytes(mlkem_poly *r, const uint8_t a[KYBER_POLYBYTES])
{
  unsigned int i;
  for(i=0;i<KYBER_N/2;i++) {
    r->coeffs[2*i]   = ((a[3*i+0] >> 0) | ((uint16_t)a[3*i+1] << 8)) & 0xFFF;
    r->coeffs[2*i+1] = ((a[3*i+1] >> 4) | ((uint16_t)a[3*i+2] << 4)) & 0xFFF;
  }
}

/*************************************************
* Name:        mlkem_poly_frommsg
*
* Description: Convert 32-byte message to polynomial
*
* Arguments:   - mlkem_poly *r: pointer to output polynomial
*              - const uint8_t *msg: pointer to input message
**************************************************/
static void mlkem_poly_frommsg(mlkem_poly *r, const uint8_t msg[KYBER_INDCPA_MSGBYTES])
{
  unsigned int i,j;

#if (KYBER_INDCPA_MSGBYTES != KYBER_N/8)
#error "KYBER_INDCPA_MSGBYTES must be equal to KYBER_N/8 bytes!"
#endif

  for(i=0;i<KYBER_N/8;i++) {
    for(j=0;j<8;j++) {
      r->coeffs[8*i+j] = 0;
      mlkem_cmov_int16(r->coeffs+8*i+j, ((KYBER_Q+1)/2), (msg[i] >> j)&1);
    }
  }
}

/*************************************************
* Name:        mlkem_poly_tomsg
*
* Description: Convert polynomial to 32-byte message
*
* Arguments:   - uint8_t *msg: pointer to output message
*              - const mlkem_poly *a: pointer to input polynomial
**************************************************/
static void mlkem_poly_tomsg(uint8_t msg[KYBER_INDCPA_MSGBYTES], const mlkem_poly *a)
{
  unsigned int i,j;
  uint32_t t;

  for(i=0;i<KYBER_N/8;i++) {
    msg[i] = 0;
    for(j=0;j<8;j++) {
      t  = a->coeffs[8*i+j];
      // t += ((int16_t)t >> 15) & KYBER_Q;
      // t  = (((t << 1) + KYBER_Q/2)/KYBER_Q) & 1;
      t <<= 1;
      t += 1665;
      t *= 80635;
      t >>= 28;
      t &= 1;
      msg[i] |= t << j;
    }
  }
}

/*************************************************
* Name:        mlkem_poly_getnoise_eta1
*
* Description: Sample a polynomial deterministically from a seed and a nonce,
*              with output polynomial close to centered binomial distribution
*              with parameter KYBER_ETA1
*
* Arguments:   - mlkem_poly *r: pointer to output polynomial
*              - const uint8_t *seed: pointer to input seed
*                                     (of length KYBER_SYMBYTES bytes)
*              - uint8_t nonce: one-byte input nonce
**************************************************/
static void mlkem_poly_getnoise_eta1(mlkem_poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce)
{
  uint8_t buf[KYBER_ETA1*KYBER_N/4];
  prf(buf, sizeof(buf), seed, nonce);
  mlkem_poly_cbd_eta1(r, buf);
}

/*************************************************
* Name:        mlkem_poly_getnoise_eta2
*
* Description: Sample a polynomial deterministically from a seed and a nonce,
*              with output polynomial close to centered binomial distribution
*              with parameter KYBER_ETA2
*
* Arguments:   - mlkem_poly *r: pointer to output polynomial
*              - const uint8_t *seed: pointer to input seed
*                                     (of length KYBER_SYMBYTES bytes)
*              - uint8_t nonce: one-byte input nonce
**************************************************/
static void mlkem_poly_getnoise_eta2(mlkem_poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce)
{
  uint8_t buf[KYBER_ETA2*KYBER_N/4];
  prf(buf, sizeof(buf), seed, nonce);
  mlkem_poly_cbd_eta2(r, buf);
}


/*************************************************
* Name:        mlkem_poly_ntt
*
* Description: Computes negacyclic number-theoretic transform (NTT) of
*              a polynomial in place;
*              inputs assumed to be in normal order, output in bitreversed order
*
* Arguments:   - uint16_t *r: pointer to in/output polynomial
**************************************************/
static void mlkem_poly_ntt(mlkem_poly *r)
{
  mlkem_ntt(r->coeffs);
  mlkem_poly_reduce(r);
}

/*************************************************
* Name:        mlkem_poly_invntt_tomont
*
* Description: Computes inverse of negacyclic number-theoretic transform (NTT)
*              of a polynomial in place;
*              inputs assumed to be in bitreversed order, output in normal order
*
* Arguments:   - uint16_t *a: pointer to in/output polynomial
**************************************************/
static void mlkem_poly_invntt_tomont(mlkem_poly *r)
{
  mlkem_invntt(r->coeffs);
}

/*************************************************
* Name:        mlkem_poly_basemul_montgomery
*
* Description: Multiplication of two polynomials in NTT domain
*
* Arguments:   - mlkem_poly *r: pointer to output polynomial
*              - const mlkem_poly *a: pointer to first input polynomial
*              - const mlkem_poly *b: pointer to second input polynomial
**************************************************/
static void mlkem_poly_basemul_montgomery(mlkem_poly *r, const mlkem_poly *a, const mlkem_poly *b)
{
  unsigned int i;
  for(i=0;i<KYBER_N/4;i++) {
    mlkem_basemul(&r->coeffs[4*i], &a->coeffs[4*i], &b->coeffs[4*i], mlkem_zetas[64+i]);
    mlkem_basemul(&r->coeffs[4*i+2], &a->coeffs[4*i+2], &b->coeffs[4*i+2], -mlkem_zetas[64+i]);
  }
}

/*************************************************
* Name:        mlkem_poly_tomont
*
* Description: Inplace conversion of all coefficients of a polynomial
*              from normal domain to Montgomery domain
*
* Arguments:   - mlkem_poly *r: pointer to input/output polynomial
**************************************************/
static void mlkem_poly_tomont(mlkem_poly *r)
{
  unsigned int i;
  const int16_t f = (1ULL << 32) % KYBER_Q;
  for(i=0;i<KYBER_N;i++)
    r->coeffs[i] = mlkem_montgomery_reduce((int32_t)r->coeffs[i]*f);
}

/*************************************************
* Name:        mlkem_poly_reduce
*
* Description: Applies Barrett reduction to all coefficients of a polynomial
*              for details of the Barrett reduction see comments in reduce.c
*
* Arguments:   - mlkem_poly *r: pointer to input/output polynomial
**************************************************/
static void mlkem_poly_reduce(mlkem_poly *r)
{
  unsigned int i;
  for(i=0;i<KYBER_N;i++)
    r->coeffs[i] = mlkem_barrett_reduce(r->coeffs[i]);
}

/*************************************************
* Name:        mlkem_poly_add
*
* Description: Add two polynomials; no modular reduction is performed
*
* Arguments: - mlkem_poly *r: pointer to output polynomial
*            - const mlkem_poly *a: pointer to first input polynomial
*            - const mlkem_poly *b: pointer to second input polynomial
**************************************************/
static void mlkem_poly_add(mlkem_poly *r, const mlkem_poly *a, const mlkem_poly *b)
{
  unsigned int i;
  for(i=0;i<KYBER_N;i++)
    r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

/*************************************************
* Name:        mlkem_poly_sub
*
* Description: Subtract two polynomials; no modular reduction is performed
*
* Arguments: - mlkem_poly *r:       pointer to output polynomial
*            - const mlkem_poly *a: pointer to first input polynomial
*            - const mlkem_poly *b: pointer to second input polynomial
**************************************************/
static void mlkem_poly_sub(mlkem_poly *r, const mlkem_poly *a, const mlkem_poly *b)
{
  unsigned int i;
  for(i=0;i<KYBER_N;i++)
    r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

// ----- mlkem/polyvec.c -----
/*************************************************
* Name:        mlkem_polyvec_compress
*
* Description: Compress and serialize vector of polynomials
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (needs space for KYBER_POLYVECCOMPRESSEDBYTES)
*              - const mlkem_polyvec *a: pointer to input vector of polynomials
**************************************************/
static void mlkem_polyvec_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES], const mlkem_polyvec *a)
{
  unsigned int i,j,k;
  uint64_t d0;

#if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352))
  uint16_t t[8];
  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_N/8;j++) {
      for(k=0;k<8;k++) {
        t[k]  = a->vec[i].coeffs[8*j+k];
        t[k] += ((int16_t)t[k] >> 15) & KYBER_Q;
/*      t[k]  = ((((uint32_t)t[k] << 11) + KYBER_Q/2)/KYBER_Q) & 0x7ff; */
        d0 = t[k];
        d0 <<= 11;
        d0 += 1664;
        d0 *= 645084;
        d0 >>= 31;
        t[k] = d0 & 0x7ff;

      }

      r[ 0] = (t[0] >>  0);
      r[ 1] = (t[0] >>  8) | (t[1] << 3);
      r[ 2] = (t[1] >>  5) | (t[2] << 6);
      r[ 3] = (t[2] >>  2);
      r[ 4] = (t[2] >> 10) | (t[3] << 1);
      r[ 5] = (t[3] >>  7) | (t[4] << 4);
      r[ 6] = (t[4] >>  4) | (t[5] << 7);
      r[ 7] = (t[5] >>  1);
      r[ 8] = (t[5] >>  9) | (t[6] << 2);
      r[ 9] = (t[6] >>  6) | (t[7] << 5);
      r[10] = (t[7] >>  3);
      r += 11;
    }
  }
#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320))
  uint16_t t[4];
  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_N/4;j++) {
      for(k=0;k<4;k++) {
        t[k]  = a->vec[i].coeffs[4*j+k];
        t[k] += ((int16_t)t[k] >> 15) & KYBER_Q;
/*      t[k]  = ((((uint32_t)t[k] << 10) + KYBER_Q/2)/ KYBER_Q) & 0x3ff; */
        d0 = t[k];
        d0 <<= 10;
        d0 += 1665;
        d0 *= 1290167;
        d0 >>= 32;
        t[k] = d0 & 0x3ff;
      }

      r[0] = (t[0] >> 0);
      r[1] = (t[0] >> 8) | (t[1] << 2);
      r[2] = (t[1] >> 6) | (t[2] << 4);
      r[3] = (t[2] >> 4) | (t[3] << 6);
      r[4] = (t[3] >> 2);
      r += 5;
    }
  }
#else
#error "KYBER_POLYVECCOMPRESSEDBYTES needs to be in {320*KYBER_K, 352*KYBER_K}"
#endif
}

/*************************************************
* Name:        mlkem_polyvec_decompress
*
* Description: De-serialize and decompress vector of polynomials;
*              approximate inverse of mlkem_polyvec_compress
*
* Arguments:   - mlkem_polyvec *r:       pointer to output vector of polynomials
*              - const uint8_t *a: pointer to input byte array
*                                  (of length KYBER_POLYVECCOMPRESSEDBYTES)
**************************************************/
static void mlkem_polyvec_decompress(mlkem_polyvec *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES])
{
  unsigned int i,j,k;

#if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352))
  uint16_t t[8];
  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_N/8;j++) {
      t[0] = (a[0] >> 0) | ((uint16_t)a[ 1] << 8);
      t[1] = (a[1] >> 3) | ((uint16_t)a[ 2] << 5);
      t[2] = (a[2] >> 6) | ((uint16_t)a[ 3] << 2) | ((uint16_t)a[4] << 10);
      t[3] = (a[4] >> 1) | ((uint16_t)a[ 5] << 7);
      t[4] = (a[5] >> 4) | ((uint16_t)a[ 6] << 4);
      t[5] = (a[6] >> 7) | ((uint16_t)a[ 7] << 1) | ((uint16_t)a[8] << 9);
      t[6] = (a[8] >> 2) | ((uint16_t)a[ 9] << 6);
      t[7] = (a[9] >> 5) | ((uint16_t)a[10] << 3);
      a += 11;

      for(k=0;k<8;k++)
        r->vec[i].coeffs[8*j+k] = ((uint32_t)(t[k] & 0x7FF)*KYBER_Q + 1024) >> 11;
    }
  }
#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320))
  uint16_t t[4];
  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_N/4;j++) {
      t[0] = (a[0] >> 0) | ((uint16_t)a[1] << 8);
      t[1] = (a[1] >> 2) | ((uint16_t)a[2] << 6);
      t[2] = (a[2] >> 4) | ((uint16_t)a[3] << 4);
      t[3] = (a[3] >> 6) | ((uint16_t)a[4] << 2);
      a += 5;

      for(k=0;k<4;k++)
        r->vec[i].coeffs[4*j+k] = ((uint32_t)(t[k] & 0x3FF)*KYBER_Q + 512) >> 10;
    }
  }
#else
#error "KYBER_POLYVECCOMPRESSEDBYTES needs to be in {320*KYBER_K, 352*KYBER_K}"
#endif
}

/*************************************************
* Name:        mlkem_polyvec_tobytes
*
* Description: Serialize vector of polynomials
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (needs space for KYBER_POLYVECBYTES)
*              - const mlkem_polyvec *a: pointer to input vector of polynomials
**************************************************/
static void mlkem_polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], const mlkem_polyvec *a)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    mlkem_poly_tobytes(r+i*KYBER_POLYBYTES, &a->vec[i]);
}

/*************************************************
* Name:        mlkem_polyvec_frombytes
*
* Description: De-serialize vector of polynomials;
*              inverse of mlkem_polyvec_tobytes
*
* Arguments:   - uint8_t *r:       pointer to output byte array
*              - const mlkem_polyvec *a: pointer to input vector of polynomials
*                                  (of length KYBER_POLYVECBYTES)
**************************************************/
static void mlkem_polyvec_frombytes(mlkem_polyvec *r, const uint8_t a[KYBER_POLYVECBYTES])
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    mlkem_poly_frombytes(&r->vec[i], a+i*KYBER_POLYBYTES);
}

/*************************************************
* Name:        mlkem_polyvec_ntt
*
* Description: Apply forward NTT to all elements of a vector of polynomials
*
* Arguments:   - mlkem_polyvec *r: pointer to in/output vector of polynomials
**************************************************/
static void mlkem_polyvec_ntt(mlkem_polyvec *r)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    mlkem_poly_ntt(&r->vec[i]);
}

/*************************************************
* Name:        mlkem_polyvec_invntt_tomont
*
* Description: Apply inverse NTT to all elements of a vector of polynomials
*              and multiply by Montgomery factor 2^16
*
* Arguments:   - mlkem_polyvec *r: pointer to in/output vector of polynomials
**************************************************/
static void mlkem_polyvec_invntt_tomont(mlkem_polyvec *r)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    mlkem_poly_invntt_tomont(&r->vec[i]);
}

/*************************************************
* Name:        mlkem_polyvec_basemul_acc_montgomery
*
* Description: Multiply elements of a and b in NTT domain, accumulate into r,
*              and multiply by 2^-16.
*
* Arguments: - mlkem_poly *r: pointer to output polynomial
*            - const mlkem_polyvec *a: pointer to first input vector of polynomials
*            - const mlkem_polyvec *b: pointer to second input vector of polynomials
**************************************************/
static void mlkem_polyvec_basemul_acc_montgomery(mlkem_poly *r, const mlkem_polyvec *a, const mlkem_polyvec *b)
{
  unsigned int i;
  mlkem_poly t;

  mlkem_poly_basemul_montgomery(r, &a->vec[0], &b->vec[0]);
  for(i=1;i<KYBER_K;i++) {
    mlkem_poly_basemul_montgomery(&t, &a->vec[i], &b->vec[i]);
    mlkem_poly_add(r, r, &t);
  }

  mlkem_poly_reduce(r);
}

/*************************************************
* Name:        mlkem_polyvec_reduce
*
* Description: Applies Barrett reduction to each coefficient
*              of each element of a vector of polynomials;
*              for details of the Barrett reduction see comments in reduce.c
*
* Arguments:   - mlkem_polyvec *r: pointer to input/output polynomial
**************************************************/
static void mlkem_polyvec_reduce(mlkem_polyvec *r)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    mlkem_poly_reduce(&r->vec[i]);
}

/*************************************************
* Name:        mlkem_polyvec_add
*
* Description: Add vectors of polynomials
*
* Arguments: - mlkem_polyvec *r: pointer to output vector of polynomials
*            - const mlkem_polyvec *a: pointer to first input vector of polynomials
*            - const mlkem_polyvec *b: pointer to second input vector of polynomials
**************************************************/
static void mlkem_polyvec_add(mlkem_polyvec *r, const mlkem_polyvec *a, const mlkem_polyvec *b)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    mlkem_poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
}

// ----- mlkem/verify.c -----
/*************************************************
* Name:        mlkem_verify
*
* Description: Compare two arrays for equality in constant time.
*
* Arguments:   const uint8_t *a: pointer to first byte array
*              const uint8_t *b: pointer to second byte array
*              size_t len:       length of the byte arrays
*
* Returns 0 if the byte arrays are equal, 1 otherwise
**************************************************/
static int mlkem_verify(const uint8_t *a, const uint8_t *b, size_t len)
{
  size_t i;
  uint8_t r = 0;

  for(i=0;i<len;i++)
    r |= a[i] ^ b[i];

  return (-(uint64_t)r) >> 63;
}

/*************************************************
* Name:        mlkem_cmov
*
* Description: Copy len bytes from x to r if b is 1;
*              don't modify x if b is 0. Requires b to be in {0,1};
*              assumes two's complement representation of negative integers.
*              Runs in constant time.
*
* Arguments:   uint8_t *r:       pointer to output byte array
*              const uint8_t *x: pointer to input byte array
*              size_t len:       Amount of bytes to be copied
*              uint8_t b:        Condition bit; has to be in {0,1}
**************************************************/
static void mlkem_cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b)
{
  size_t i;

  b = -b;
  for(i=0;i<len;i++)
    r[i] ^= b & (r[i] ^ x[i]);
}


/*************************************************
* Name:        mlkem_cmov_int16
*
* Description: Copy input v to *r if b is 1, don't modify *r if b is 0. 
*              Requires b to be in {0,1};
*              Runs in constant time.
*
* Arguments:   int16_t *r:       pointer to output int16_t
*              int16_t v:        input int16_t 
*              uint8_t b:        Condition bit; has to be in {0,1}
**************************************************/
static void mlkem_cmov_int16(int16_t *r, int16_t v, uint16_t b)
{
  b = -b;
  *r ^= b & ((*r) ^ v);
}

// ----- mlkem/symmetric-shake.c -----
/*************************************************
* Name:        mlkem_shake128_absorb
*
* Description: Absorb step of the SHAKE128 specialized for the Kyber context.
*
* Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak state
*              - const uint8_t *seed: pointer to KYBER_SYMBYTES input to be absorbed into state
*              - uint8_t i: additional byte of input
*              - uint8_t j: additional byte of input
**************************************************/
static void mlkem_shake128_absorb(keccak_state *state,
                           const uint8_t seed[KYBER_SYMBYTES],
                           uint8_t x,
                           uint8_t y)
{
  uint8_t extseed[KYBER_SYMBYTES+2];

  memcpy(extseed, seed, KYBER_SYMBYTES);
  extseed[KYBER_SYMBYTES+0] = x;
  extseed[KYBER_SYMBYTES+1] = y;

  shake128_absorb_once(state, extseed, sizeof(extseed));
}

/*************************************************
* Name:        mlkem_shake256_prf
*
* Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
*              and then generates outlen bytes of SHAKE256 output
*
* Arguments:   - uint8_t *out: pointer to output
*              - size_t outlen: number of requested output bytes
*              - const uint8_t *key: pointer to the key (of length KYBER_SYMBYTES)
*              - uint8_t nonce: single-byte nonce (public PRF input)
**************************************************/
static void mlkem_shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce)
{
  uint8_t extkey[KYBER_SYMBYTES+1];

  memcpy(extkey, key, KYBER_SYMBYTES);
  extkey[KYBER_SYMBYTES] = nonce;

  shake256(out, outlen, extkey, sizeof(extkey));
}

/*************************************************
* Name:        mlkem_shake256_prf
*
* Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
*              and then generates outlen bytes of SHAKE256 output
*
* Arguments:   - uint8_t *out: pointer to output
*              - size_t outlen: number of requested output bytes
*              - const uint8_t *key: pointer to the key (of length KYBER_SYMBYTES)
*              - uint8_t nonce: single-byte nonce (public PRF input)
**************************************************/
static void mlkem_shake256_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES])
{
  keccak_state s;

  shake256_init(&s);
  shake256_absorb(&s, key, KYBER_SYMBYTES);
  shake256_absorb(&s, input, KYBER_CIPHERTEXTBYTES);
  shake256_finalize(&s);
  shake256_squeeze(out, KYBER_SSBYTES, &s);
}

// ----- mlkem/indcpa.c -----
/*************************************************
* Name:        pack_pk
*
* Description: Serialize the public key as concatenation of the
*              serialized vector of polynomials pk
*              and the public seed used to generate the matrix A.
*
* Arguments:   uint8_t *r: pointer to the output serialized public key
*              mlkem_polyvec *pk: pointer to the input public-key mlkem_polyvec
*              const uint8_t *seed: pointer to the input public seed
**************************************************/
static void pack_pk(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES],
                    mlkem_polyvec *pk,
                    const uint8_t seed[KYBER_SYMBYTES])
{
  mlkem_polyvec_tobytes(r, pk);
  memcpy(r+KYBER_POLYVECBYTES, seed, KYBER_SYMBYTES);
}

/*************************************************
* Name:        unpack_pk
*
* Description: De-serialize public key from a byte array;
*              approximate inverse of pack_pk
*
* Arguments:   - mlkem_polyvec *pk: pointer to output public-key polynomial vector
*              - uint8_t *seed: pointer to output seed to generate matrix A
*              - const uint8_t *packedpk: pointer to input serialized public key
**************************************************/
static void unpack_pk(mlkem_polyvec *pk,
                      uint8_t seed[KYBER_SYMBYTES],
                      const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES])
{
  mlkem_polyvec_frombytes(pk, packedpk);
  memcpy(seed, packedpk+KYBER_POLYVECBYTES, KYBER_SYMBYTES);
}

/*************************************************
* Name:        pack_sk
*
* Description: Serialize the secret key
*
* Arguments:   - uint8_t *r: pointer to output serialized secret key
*              - mlkem_polyvec *sk: pointer to input vector of polynomials (secret key)
**************************************************/
static void pack_sk(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES], mlkem_polyvec *sk)
{
  mlkem_polyvec_tobytes(r, sk);
}

/*************************************************
* Name:        unpack_sk
*
* Description: De-serialize the secret key; inverse of pack_sk
*
* Arguments:   - mlkem_polyvec *sk: pointer to output vector of polynomials (secret key)
*              - const uint8_t *packedsk: pointer to input serialized secret key
**************************************************/
static void unpack_sk(mlkem_polyvec *sk, const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES])
{
  mlkem_polyvec_frombytes(sk, packedsk);
}

/*************************************************
* Name:        pack_ciphertext
*
* Description: Serialize the ciphertext as concatenation of the
*              compressed and serialized vector of polynomials b
*              and the compressed and serialized polynomial v
*
* Arguments:   uint8_t *r: pointer to the output serialized ciphertext
*              mlkem_poly *pk: pointer to the input vector of polynomials b
*              mlkem_poly *v: pointer to the input polynomial v
**************************************************/
static void pack_ciphertext(uint8_t r[KYBER_INDCPA_BYTES], mlkem_polyvec *b, mlkem_poly *v)
{
  mlkem_polyvec_compress(r, b);
  mlkem_poly_compress(r+KYBER_POLYVECCOMPRESSEDBYTES, v);
}

/*************************************************
* Name:        unpack_ciphertext
*
* Description: De-serialize and decompress ciphertext from a byte array;
*              approximate inverse of pack_ciphertext
*
* Arguments:   - mlkem_polyvec *b: pointer to the output vector of polynomials b
*              - mlkem_poly *v: pointer to the output polynomial v
*              - const uint8_t *c: pointer to the input serialized ciphertext
**************************************************/
static void unpack_ciphertext(mlkem_polyvec *b, mlkem_poly *v, const uint8_t c[KYBER_INDCPA_BYTES])
{
  mlkem_polyvec_decompress(b, c);
  mlkem_poly_decompress(v, c+KYBER_POLYVECCOMPRESSEDBYTES);
}

/*************************************************
* Name:        mlkem_rej_uniform
*
* Description: Run rejection sampling on uniform random bytes to generate
*              uniform random integers mod q
*
* Arguments:   - int16_t *r: pointer to output buffer
*              - unsigned int len: requested number of 16-bit integers (uniform mod q)
*              - const uint8_t *buf: pointer to input buffer (assumed to be uniformly random bytes)
*              - unsigned int buflen: length of input buffer in bytes
*
* Returns number of sampled 16-bit integers (at most len)
**************************************************/
static unsigned int mlkem_rej_uniform(int16_t *r,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen)
{
  unsigned int ctr, pos;
  uint16_t val0, val1;

  ctr = pos = 0;
  while(ctr < len && pos + 3 <= buflen) {
    val0 = ((buf[pos+0] >> 0) | ((uint16_t)buf[pos+1] << 8)) & 0xFFF;
    val1 = ((buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4)) & 0xFFF;
    pos += 3;

    if(val0 < KYBER_Q)
      r[ctr++] = val0;
    if(ctr < len && val1 < KYBER_Q)
      r[ctr++] = val1;
  }

  return ctr;
}

#define gen_a(A,B)  mlkem_gen_matrix(A,B,0)
#define gen_at(A,B) mlkem_gen_matrix(A,B,1)

/*************************************************
* Name:        mlkem_gen_matrix
*
* Description: Deterministically generate matrix A (or the transpose of A)
*              from a seed. Entries of the matrix are polynomials that look
*              uniformly random. Performs rejection sampling on output of
*              a XOF
*
* Arguments:   - mlkem_polyvec *a: pointer to ouptput matrix A
*              - const uint8_t *seed: pointer to input seed
*              - int transposed: boolean deciding whether A or A^T is generated
**************************************************/
#if(XOF_BLOCKBYTES % 3)
#error "Implementation of mlkem_gen_matrix assumes that XOF_BLOCKBYTES is a multiple of 3"
#endif

#define GEN_MATRIX_NBLOCKS ((12*KYBER_N/8*(1 << 12)/KYBER_Q + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)
// Not static for benchmarking
static void mlkem_gen_matrix(mlkem_polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed)
{
  unsigned int ctr, i, j;
  unsigned int buflen;
  uint8_t buf[GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES];
  mlkem_xof_state state;

  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_K;j++) {
      if(transposed)
        xof_absorb(&state, seed, i, j);
      else
        xof_absorb(&state, seed, j, i);

      xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state);
      buflen = GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES;
      ctr = mlkem_rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf, buflen);

      while(ctr < KYBER_N) {
        xof_squeezeblocks(buf, 1, &state);
        buflen = XOF_BLOCKBYTES;
        ctr += mlkem_rej_uniform(a[i].vec[j].coeffs + ctr, KYBER_N - ctr, buf, buflen);
      }
    }
  }
}

/*************************************************
* Name:        mlkem_indcpa_keypair_derand
*
* Description: Generates public and private key for the CPA-secure
*              public-key encryption scheme underlying Kyber
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                             (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
*                             (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
*              - const uint8_t *coins: pointer to input randomness
*                             (of length KYBER_SYMBYTES bytes)
**************************************************/
static void mlkem_indcpa_keypair_derand(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                           uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
                           const uint8_t coins[KYBER_SYMBYTES])
{
  unsigned int i;
  uint8_t buf[2*KYBER_SYMBYTES];
  const uint8_t *publicseed = buf;
  const uint8_t *noiseseed = buf+KYBER_SYMBYTES;
  uint8_t nonce = 0;
  mlkem_polyvec a[KYBER_K], e, pkpv, skpv;

  memcpy(buf, coins, KYBER_SYMBYTES);
  buf[KYBER_SYMBYTES] = KYBER_K;
  hash_g(buf, buf, KYBER_SYMBYTES+1);

  gen_a(a, publicseed);

  for(i=0;i<KYBER_K;i++)
    mlkem_poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++);
  for(i=0;i<KYBER_K;i++)
    mlkem_poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++);

  mlkem_polyvec_ntt(&skpv);
  mlkem_polyvec_ntt(&e);

  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++) {
    mlkem_polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
    mlkem_poly_tomont(&pkpv.vec[i]);
  }

  mlkem_polyvec_add(&pkpv, &pkpv, &e);
  mlkem_polyvec_reduce(&pkpv);

  pack_sk(sk, &skpv);
  pack_pk(pk, &pkpv, publicseed);

  ncrypt_wipe(buf,   sizeof buf);
  ncrypt_wipe(&skpv, sizeof skpv);
  ncrypt_wipe(&e,    sizeof e);
}


/*************************************************
* Name:        mlkem_indcpa_enc
*
* Description: Encryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *c: pointer to output ciphertext
*                            (of length KYBER_INDCPA_BYTES bytes)
*              - const uint8_t *m: pointer to input message
*                                  (of length KYBER_INDCPA_MSGBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                                   (of length KYBER_INDCPA_PUBLICKEYBYTES)
*              - const uint8_t *coins: pointer to input random coins used as seed
*                                      (of length KYBER_SYMBYTES) to deterministically
*                                      generate all randomness
**************************************************/
static void mlkem_indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES])
{
  unsigned int i;
  uint8_t seed[KYBER_SYMBYTES];
  uint8_t nonce = 0;
  mlkem_polyvec sp, pkpv, ep, at[KYBER_K], b;
  mlkem_poly v, k, epp;

  unpack_pk(&pkpv, seed, pk);
  mlkem_poly_frommsg(&k, m);
  gen_at(at, seed);

  for(i=0;i<KYBER_K;i++)
    mlkem_poly_getnoise_eta1(sp.vec+i, coins, nonce++);
  for(i=0;i<KYBER_K;i++)
    mlkem_poly_getnoise_eta2(ep.vec+i, coins, nonce++);
  mlkem_poly_getnoise_eta2(&epp, coins, nonce++);

  mlkem_polyvec_ntt(&sp);

  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++)
    mlkem_polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp);

  mlkem_polyvec_basemul_acc_montgomery(&v, &pkpv, &sp);

  mlkem_polyvec_invntt_tomont(&b);
  mlkem_poly_invntt_tomont(&v);

  mlkem_polyvec_add(&b, &b, &ep);
  mlkem_poly_add(&v, &v, &epp);
  mlkem_poly_add(&v, &v, &k);
  mlkem_polyvec_reduce(&b);
  mlkem_poly_reduce(&v);

  pack_ciphertext(c, &b, &v);

  ncrypt_wipe(&sp,  sizeof sp);
  ncrypt_wipe(&ep,  sizeof ep);
  ncrypt_wipe(&epp, sizeof epp);
  ncrypt_wipe(&k,   sizeof k);
  ncrypt_wipe(&v,   sizeof v);
}

/*************************************************
* Name:        mlkem_indcpa_dec
*
* Description: Decryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *m: pointer to output decrypted message
*                            (of length KYBER_INDCPA_MSGBYTES)
*              - const uint8_t *c: pointer to input ciphertext
*                                  (of length KYBER_INDCPA_BYTES)
*              - const uint8_t *sk: pointer to input secret key
*                                   (of length KYBER_INDCPA_SECRETKEYBYTES)
**************************************************/
static void mlkem_indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES])
{
  mlkem_polyvec b, skpv;
  mlkem_poly v, mp;

  unpack_ciphertext(&b, &v, c);
  unpack_sk(&skpv, sk);

  mlkem_polyvec_ntt(&b);
  mlkem_polyvec_basemul_acc_montgomery(&mp, &skpv, &b);
  mlkem_poly_invntt_tomont(&mp);

  mlkem_poly_sub(&mp, &v, &mp);
  mlkem_poly_reduce(&mp);

  mlkem_poly_tomsg(m, &mp);

  ncrypt_wipe(&skpv, sizeof skpv);
  ncrypt_wipe(&mp,   sizeof mp);
  ncrypt_wipe(&v,    sizeof v);
}

// ----- mlkem/kem.c -----
/*************************************************
* Name:        mlkem_keypair_derand
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*              - uint8_t *coins: pointer to input randomness
*                (an already allocated array filled with 2*KYBER_SYMBYTES random bytes)
**
* Returns 0 (success)
**************************************************/
static int mlkem_keypair_derand(uint8_t *pk,
                              uint8_t *sk,
                              const uint8_t *coins)
{
  mlkem_indcpa_keypair_derand(pk, sk, coins);
  memcpy(sk+KYBER_INDCPA_SECRETKEYBYTES, pk, KYBER_PUBLICKEYBYTES);
  hash_h(sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  /* Value z for pseudo-random output on reject */
  memcpy(sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, coins+KYBER_SYMBYTES, KYBER_SYMBYTES);
  return 0;
}


/*************************************************
* Name:        mlkem_enc_derand
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - uint8_t *ct: pointer to output cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*              - const uint8_t *coins: pointer to input randomness
*                (an already allocated array filled with KYBER_SYMBYTES random bytes)
**
* Returns 0 (success)
**************************************************/
static int mlkem_enc_derand(uint8_t *ct,
                          uint8_t *ss,
                          const uint8_t *pk,
                          const uint8_t *coins)
{
  uint8_t buf[2*KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];

  memcpy(buf, coins, KYBER_SYMBYTES);

  /* Multitarget countermeasure for coins + contributory KEM */
  hash_h(buf+KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  hash_g(kr, buf, 2*KYBER_SYMBYTES);

  /* coins are in kr+KYBER_SYMBYTES */
  mlkem_indcpa_enc(ct, buf, pk, kr+KYBER_SYMBYTES);

  memcpy(ss,kr,KYBER_SYMBYTES);
  ncrypt_wipe(buf, sizeof buf);
  ncrypt_wipe(kr,  sizeof kr);
  return 0;
}


/*************************************************
* Name:        mlkem_dec
*
* Description: Generates shared secret for given
*              cipher text and private key
*
* Arguments:   - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *ct: pointer to input cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - const uint8_t *sk: pointer to input private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*
* Returns 0.
*
* On failure, ss will contain a pseudo-random value.
**************************************************/
static int mlkem_dec(uint8_t *ss,
                   const uint8_t *ct,
                   const uint8_t *sk)
{
  int fail;
  uint8_t buf[2*KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];
  uint8_t cmp[KYBER_CIPHERTEXTBYTES+KYBER_SYMBYTES];
  const uint8_t *pk = sk+KYBER_INDCPA_SECRETKEYBYTES;

  mlkem_indcpa_dec(buf, ct, sk);

  /* Multitarget countermeasure for coins + contributory KEM */
  memcpy(buf+KYBER_SYMBYTES, sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, KYBER_SYMBYTES);
  hash_g(kr, buf, 2*KYBER_SYMBYTES);

  /* coins are in kr+KYBER_SYMBYTES */
  mlkem_indcpa_enc(cmp, buf, pk, kr+KYBER_SYMBYTES);

  fail = mlkem_verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

  /* Compute rejection key */
  rkprf(ss,sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES,ct);

  /* Copy true key to return buffer if fail is false */
  mlkem_cmov(ss,kr,KYBER_SYMBYTES,!fail);

  ncrypt_wipe(buf, sizeof buf);
  ncrypt_wipe(kr,  sizeof kr);
  ncrypt_wipe(cmp, sizeof cmp);
  return 0;
}

// ----- mldsa/params.h -----
#define MLDSA_SEEDBYTES 32
#define MLDSA_CRHBYTES 64
#define MLDSA_TRBYTES 64
#define MLDSA_RNDBYTES 32
#define MLDSA_N 256
#define MLDSA_Q 8380417
#define MLDSA_D 13
#define MLDSA_ROOT_OF_UNITY 1753

#if DILITHIUM_MODE == 2
#define MLDSA_K 4
#define MLDSA_L 4
#define MLDSA_ETA 2
#define MLDSA_TAU 39
#define MLDSA_BETA 78
#define MLDSA_GAMMA1 (1 << 17)
#define MLDSA_GAMMA2 ((MLDSA_Q-1)/88)
#define MLDSA_OMEGA 80
#define MLDSA_CTILDEBYTES 32

#elif DILITHIUM_MODE == 3
#define MLDSA_K 6
#define MLDSA_L 5
#define MLDSA_ETA 4
#define MLDSA_TAU 49
#define MLDSA_BETA 196
#define MLDSA_GAMMA1 (1 << 19)
#define MLDSA_GAMMA2 ((MLDSA_Q-1)/32)
#define MLDSA_OMEGA 55
#define MLDSA_CTILDEBYTES 48

#elif DILITHIUM_MODE == 5
#define MLDSA_K 8
#define MLDSA_L 7
#define MLDSA_ETA 2
#define MLDSA_TAU 60
#define MLDSA_BETA 120
#define MLDSA_GAMMA1 (1 << 19)
#define MLDSA_GAMMA2 ((MLDSA_Q-1)/32)
#define MLDSA_OMEGA 75
#define MLDSA_CTILDEBYTES 64

#endif

#define MLDSA_POLYT1_PACKEDBYTES  320
#define MLDSA_POLYT0_PACKEDBYTES  416
#define MLDSA_POLYVECH_PACKEDBYTES (MLDSA_OMEGA + MLDSA_K)

#if MLDSA_GAMMA1 == (1 << 17)
#define MLDSA_POLYZ_PACKEDBYTES   576
#elif MLDSA_GAMMA1 == (1 << 19)
#define MLDSA_POLYZ_PACKEDBYTES   640
#endif

#if MLDSA_GAMMA2 == (MLDSA_Q-1)/88
#define MLDSA_POLYW1_PACKEDBYTES  192
#elif MLDSA_GAMMA2 == (MLDSA_Q-1)/32
#define MLDSA_POLYW1_PACKEDBYTES  128
#endif

#if MLDSA_ETA == 2
#define MLDSA_POLYETA_PACKEDBYTES  96
#elif MLDSA_ETA == 4
#define MLDSA_POLYETA_PACKEDBYTES 128
#endif

#define MLDSA_CRYPTO_PUBLICKEYBYTES (MLDSA_SEEDBYTES + MLDSA_K*MLDSA_POLYT1_PACKEDBYTES)
#define MLDSA_CRYPTO_SECRETKEYBYTES (2*MLDSA_SEEDBYTES + MLDSA_TRBYTES + MLDSA_L*MLDSA_POLYETA_PACKEDBYTES + MLDSA_K*MLDSA_POLYETA_PACKEDBYTES + MLDSA_K*MLDSA_POLYT0_PACKEDBYTES)
#define MLDSA_CRYPTO_BYTES (MLDSA_CTILDEBYTES + MLDSA_L*MLDSA_POLYZ_PACKEDBYTES + MLDSA_POLYVECH_PACKEDBYTES)

// ----- mldsa/reduce.h -----
#define MLDSA_MONT -4186625 // 2^32 % MLDSA_Q
#define MLDSA_QINV 58728449 // q^(-1) mod 2^32

static int32_t mldsa_montgomery_reduce(int64_t a);

static int32_t mldsa_reduce32(int32_t a);

static int32_t mldsa_caddq(int32_t a);

// ----- mldsa/rounding.h -----
static int32_t mldsa_power2round(int32_t *a0, int32_t a);

static int32_t mldsa_decompose(int32_t *a0, int32_t a);

static unsigned int mldsa_make_hint(int32_t a0, int32_t a1);

static int32_t mldsa_use_hint(int32_t a, unsigned int hint);

// ----- mldsa/ntt.h -----
static void mldsa_ntt(int32_t a[MLDSA_N]);

static void mldsa_invntt_tomont(int32_t a[MLDSA_N]);

// ----- mldsa/poly.h -----
typedef struct {
  int32_t coeffs[MLDSA_N];
} mldsa_poly;

static void mldsa_poly_reduce(mldsa_poly *a);
static void mldsa_poly_caddq(mldsa_poly *a);

static void mldsa_poly_add(mldsa_poly *c, const mldsa_poly *a, const mldsa_poly *b);
static void mldsa_poly_sub(mldsa_poly *c, const mldsa_poly *a, const mldsa_poly *b);
static void mldsa_poly_shiftl(mldsa_poly *a);

static void mldsa_poly_ntt(mldsa_poly *a);
static void mldsa_poly_invntt_tomont(mldsa_poly *a);
static void mldsa_poly_pointwise_montgomery(mldsa_poly *c, const mldsa_poly *a, const mldsa_poly *b);

static void mldsa_poly_power2round(mldsa_poly *a1, mldsa_poly *a0, const mldsa_poly *a);
static void mldsa_poly_decompose(mldsa_poly *a1, mldsa_poly *a0, const mldsa_poly *a);
static unsigned int mldsa_poly_make_hint(mldsa_poly *h, const mldsa_poly *a0, const mldsa_poly *a1);
static void mldsa_poly_use_hint(mldsa_poly *b, const mldsa_poly *a, const mldsa_poly *h);

static int mldsa_poly_chknorm(const mldsa_poly *a, int32_t B);
static void mldsa_poly_uniform(mldsa_poly *a,
                  const uint8_t seed[MLDSA_SEEDBYTES],
                  uint16_t nonce);
static void mldsa_poly_uniform_eta(mldsa_poly *a,
                      const uint8_t seed[MLDSA_CRHBYTES],
                      uint16_t nonce);
static void mldsa_poly_uniform_gamma1(mldsa_poly *a,
                         const uint8_t seed[MLDSA_CRHBYTES],
                         uint16_t nonce);
static void mldsa_poly_challenge(mldsa_poly *c, const uint8_t seed[MLDSA_CTILDEBYTES]);

static void mldsa_polyeta_pack(uint8_t *r, const mldsa_poly *a);
static void mldsa_polyeta_unpack(mldsa_poly *r, const uint8_t *a);

static void mldsa_polyt1_pack(uint8_t *r, const mldsa_poly *a);
static void mldsa_polyt1_unpack(mldsa_poly *r, const uint8_t *a);

static void mldsa_polyt0_pack(uint8_t *r, const mldsa_poly *a);
static void mldsa_polyt0_unpack(mldsa_poly *r, const uint8_t *a);

static void mldsa_polyz_pack(uint8_t *r, const mldsa_poly *a);
static void mldsa_polyz_unpack(mldsa_poly *r, const uint8_t *a);

static void mldsa_polyw1_pack(uint8_t *r, const mldsa_poly *a);

// ----- mldsa/polyvec.h -----
/* Vectors of polynomials of length MLDSA_L */
typedef struct {
  mldsa_poly vec[MLDSA_L];
} mldsa_polyvecl;

static void mldsa_polyvecl_uniform_eta(mldsa_polyvecl *v, const uint8_t seed[MLDSA_CRHBYTES], uint16_t nonce);

static void mldsa_polyvecl_uniform_gamma1(mldsa_polyvecl *v, const uint8_t seed[MLDSA_CRHBYTES], uint16_t nonce);

static void mldsa_polyvecl_reduce(mldsa_polyvecl *v);

static void mldsa_polyvecl_add(mldsa_polyvecl *w, const mldsa_polyvecl *u, const mldsa_polyvecl *v);

static void mldsa_polyvecl_ntt(mldsa_polyvecl *v);
static void mldsa_polyvecl_invntt_tomont(mldsa_polyvecl *v);
static void mldsa_polyvecl_pointwise_poly_montgomery(mldsa_polyvecl *r, const mldsa_poly *a, const mldsa_polyvecl *v);
static void mldsa_polyvecl_pointwise_acc_montgomery(mldsa_poly *w,
                                       const mldsa_polyvecl *u,
                                       const mldsa_polyvecl *v);


static int mldsa_polyvecl_chknorm(const mldsa_polyvecl *v, int32_t B);



/* Vectors of polynomials of length MLDSA_K */
typedef struct {
  mldsa_poly vec[MLDSA_K];
} mldsa_polyveck;

static void mldsa_polyveck_uniform_eta(mldsa_polyveck *v, const uint8_t seed[MLDSA_CRHBYTES], uint16_t nonce);

static void mldsa_polyveck_reduce(mldsa_polyveck *v);
static void mldsa_polyveck_caddq(mldsa_polyveck *v);

static void mldsa_polyveck_add(mldsa_polyveck *w, const mldsa_polyveck *u, const mldsa_polyveck *v);
static void mldsa_polyveck_sub(mldsa_polyveck *w, const mldsa_polyveck *u, const mldsa_polyveck *v);
static void mldsa_polyveck_shiftl(mldsa_polyveck *v);

static void mldsa_polyveck_ntt(mldsa_polyveck *v);
static void mldsa_polyveck_invntt_tomont(mldsa_polyveck *v);
static void mldsa_polyveck_pointwise_poly_montgomery(mldsa_polyveck *r, const mldsa_poly *a, const mldsa_polyveck *v);

static int mldsa_polyveck_chknorm(const mldsa_polyveck *v, int32_t B);

static void mldsa_polyveck_power2round(mldsa_polyveck *v1, mldsa_polyveck *v0, const mldsa_polyveck *v);
static void mldsa_polyveck_decompose(mldsa_polyveck *v1, mldsa_polyveck *v0, const mldsa_polyveck *v);
static unsigned int mldsa_polyveck_make_hint(mldsa_polyveck *h,
                                const mldsa_polyveck *v0,
                                const mldsa_polyveck *v1);
static void mldsa_polyveck_use_hint(mldsa_polyveck *w, const mldsa_polyveck *v, const mldsa_polyveck *h);

static void mldsa_polyveck_pack_w1(uint8_t r[MLDSA_K*MLDSA_POLYW1_PACKEDBYTES], const mldsa_polyveck *w1);

static void mldsa_polyvec_matrix_expand(mldsa_polyvecl mat[MLDSA_K], const uint8_t rho[MLDSA_SEEDBYTES]);

static void mldsa_polyvec_matrix_pointwise_montgomery(mldsa_polyveck *t, const mldsa_polyvecl mat[MLDSA_K], const mldsa_polyvecl *v);

// ----- mldsa/packing.h -----
static void mldsa_pack_pk(uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES], const uint8_t rho[MLDSA_SEEDBYTES], const mldsa_polyveck *t1);

static void mldsa_pack_sk(uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES],
             const uint8_t rho[MLDSA_SEEDBYTES],
             const uint8_t tr[MLDSA_TRBYTES],
             const uint8_t key[MLDSA_SEEDBYTES],
             const mldsa_polyveck *t0,
             const mldsa_polyvecl *s1,
             const mldsa_polyveck *s2);

static void mldsa_pack_sig(uint8_t sig[MLDSA_CRYPTO_BYTES], const uint8_t c[MLDSA_CTILDEBYTES], const mldsa_polyvecl *z, const mldsa_polyveck *h);

static void mldsa_unpack_pk(uint8_t rho[MLDSA_SEEDBYTES], mldsa_polyveck *t1, const uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES]);

static void mldsa_unpack_sk(uint8_t rho[MLDSA_SEEDBYTES],
               uint8_t tr[MLDSA_TRBYTES],
               uint8_t key[MLDSA_SEEDBYTES],
               mldsa_polyveck *t0,
               mldsa_polyvecl *s1,
               mldsa_polyveck *s2,
               const uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES]);

static int mldsa_unpack_sig(uint8_t c[MLDSA_CTILDEBYTES], mldsa_polyvecl *z, mldsa_polyveck *h, const uint8_t sig[MLDSA_CRYPTO_BYTES]);

// ----- mldsa/symmetric.h -----
typedef keccak_state mldsa_stream128_state;
typedef keccak_state mldsa_stream256_state;

static void mldsa_shake128_stream_init(keccak_state *state,
                                    const uint8_t seed[MLDSA_SEEDBYTES],
                                    uint16_t nonce);

static void mldsa_shake256_stream_init(keccak_state *state,
                                    const uint8_t seed[MLDSA_CRHBYTES],
                                    uint16_t nonce);

#define STREAM128_BLOCKBYTES SHAKE128_RATE
#define STREAM256_BLOCKBYTES SHAKE256_RATE

#define stream128_init(STATE, SEED, NONCE) mldsa_shake128_stream_init(STATE, SEED, NONCE)
#define stream128_squeezeblocks(OUT, OUTBLOCKS, STATE) shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define stream256_init(STATE, SEED, NONCE) mldsa_shake256_stream_init(STATE, SEED, NONCE)
#define stream256_squeezeblocks(OUT, OUTBLOCKS, STATE) shake256_squeezeblocks(OUT, OUTBLOCKS, STATE)

// ----- mldsa/sign.h -----
static int mldsa_keypair_derand(uint8_t *pk, uint8_t *sk,
                               const uint8_t seed[MLDSA_SEEDBYTES]);

static int mldsa_signature_internal(uint8_t *sig,
                                   size_t *siglen,
                                   const uint8_t *m,
                                   size_t mlen,
                                   const uint8_t *pre,
                                   size_t prelen,
                                   const uint8_t rnd[MLDSA_RNDBYTES],
                                   const uint8_t *sk);

static int mldsa_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *ctx, size_t ctxlen,
                          const uint8_t *sk);

static int mldsa_verify_internal(const uint8_t *sig,
                                size_t siglen,
                                const uint8_t *m,
                                size_t mlen,
                                const uint8_t *pre,
                                size_t prelen,
                                const uint8_t *pk);

static int mldsa_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen,
                       const uint8_t *ctx, size_t ctxlen,
                       const uint8_t *pk);

// ----- mldsa/reduce.c -----
/*************************************************
* Name:        mldsa_montgomery_reduce
*
* Description: For finite field element a with -2^{31}MLDSA_Q <= a <= MLDSA_Q*2^31,
*              compute r \equiv a*2^{-32} (mod MLDSA_Q) such that -MLDSA_Q < r < MLDSA_Q.
*
* Arguments:   - int64_t: finite field element a
*
* Returns r.
**************************************************/
static int32_t mldsa_montgomery_reduce(int64_t a) {
  int32_t t;

  t = (int64_t)(int32_t)a*MLDSA_QINV;
  t = (a - (int64_t)t*MLDSA_Q) >> 32;
  return t;
}

/*************************************************
* Name:        mldsa_reduce32
*
* Description: For finite field element a with a <= 2^{31} - 2^{22} - 1,
*              compute r \equiv a (mod MLDSA_Q) such that -6283008 <= r <= 6283008.
*
* Arguments:   - int32_t: finite field element a
*
* Returns r.
**************************************************/
static int32_t mldsa_reduce32(int32_t a) {
  int32_t t;

  t = (a + (1 << 22)) >> 23;
  t = a - t*MLDSA_Q;
  return t;
}

/*************************************************
* Name:        mldsa_caddq
*
* Description: Add MLDSA_Q if input coefficient is negative.
*
* Arguments:   - int32_t: finite field element a
*
* Returns r.
**************************************************/
static int32_t mldsa_caddq(int32_t a) {
  a += (a >> 31) & MLDSA_Q;
  return a;
}

// ----- mldsa/rounding.c -----
/*************************************************
* Name:        mldsa_power2round
*
* Description: For finite field element a, compute a0, a1 such that
*              a mod^+ MLDSA_Q = a1*2^MLDSA_D + a0 with -2^{MLDSA_D-1} < a0 <= 2^{MLDSA_D-1}.
*              Assumes a to be standard representative.
*
* Arguments:   - int32_t a: input element
*              - int32_t *a0: pointer to output element a0
*
* Returns a1.
**************************************************/
static int32_t mldsa_power2round(int32_t *a0, int32_t a)  {
  int32_t a1;

  a1 = (a + (1 << (MLDSA_D-1)) - 1) >> MLDSA_D;
  *a0 = a - (a1 << MLDSA_D);
  return a1;
}

/*************************************************
* Name:        mldsa_decompose
*
* Description: For finite field element a, compute high and low bits a0, a1 such
*              that a mod^+ MLDSA_Q = a1*ALPHA + a0 with -ALPHA/2 < a0 <= ALPHA/2 except
*              if a1 = (MLDSA_Q-1)/ALPHA where we set a1 = 0 and
*              -ALPHA/2 <= a0 = a mod^+ MLDSA_Q - MLDSA_Q < 0. Assumes a to be standard
*              representative.
*
* Arguments:   - int32_t a: input element
*              - int32_t *a0: pointer to output element a0
*
* Returns a1.
**************************************************/
static int32_t mldsa_decompose(int32_t *a0, int32_t a) {
  int32_t a1;

  a1  = (a + 127) >> 7;
#if MLDSA_GAMMA2 == (MLDSA_Q-1)/32
  a1  = (a1*1025 + (1 << 21)) >> 22;
  a1 &= 15;
#elif MLDSA_GAMMA2 == (MLDSA_Q-1)/88
  a1  = (a1*11275 + (1 << 23)) >> 24;
  a1 ^= ((43 - a1) >> 31) & a1;
#endif

  *a0  = a - a1*2*MLDSA_GAMMA2;
  *a0 -= (((MLDSA_Q-1)/2 - *a0) >> 31) & MLDSA_Q;
  return a1;
}

/*************************************************
* Name:        mldsa_make_hint
*
* Description: Compute hint bit indicating whether the low bits of the
*              input element overflow into the high bits.
*
* Arguments:   - int32_t a0: low bits of input element
*              - int32_t a1: high bits of input element
*
* Returns 1 if overflow.
**************************************************/
static unsigned int mldsa_make_hint(int32_t a0, int32_t a1) {
  if(a0 > MLDSA_GAMMA2 || a0 < -MLDSA_GAMMA2 || (a0 == -MLDSA_GAMMA2 && a1 != 0))
    return 1;

  return 0;
}

/*************************************************
* Name:        mldsa_use_hint
*
* Description: Correct high bits according to hint.
*
* Arguments:   - int32_t a: input element
*              - unsigned int hint: hint bit
*
* Returns corrected high bits.
**************************************************/
static int32_t mldsa_use_hint(int32_t a, unsigned int hint) {
  int32_t a0, a1;

  a1 = mldsa_decompose(&a0, a);
  if(hint == 0)
    return a1;

#if MLDSA_GAMMA2 == (MLDSA_Q-1)/32
  if(a0 > 0)
    return (a1 + 1) & 15;
  else
    return (a1 - 1) & 15;
#elif MLDSA_GAMMA2 == (MLDSA_Q-1)/88
  if(a0 > 0)
    return (a1 == 43) ?  0 : a1 + 1;
  else
    return (a1 ==  0) ? 43 : a1 - 1;
#endif
}

// ----- mldsa/ntt.c -----
static const int32_t zetas[MLDSA_N] = {
         0,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
   1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
   2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
  -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
   2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
  -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
  -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
  -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
  -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
   3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
   -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
  -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
  -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
    189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
   1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
   2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
    266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
    900702,  1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
   -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
    342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
   2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
  -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
  -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
  -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
   -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
  -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
  -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
  -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
   -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
  -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687,
   -554416,  3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782
};

/*************************************************
* Name:        mldsa_ntt
*
* Description: Forward NTT, in-place. No modular reduction is performed after
*              additions or subtractions. Output vector is in bitreversed order.
*
* Arguments:   - uint32_t p[MLDSA_N]: input/output coefficient array
**************************************************/
static void mldsa_ntt(int32_t a[MLDSA_N]) {
  unsigned int len, start, j, k;
  int32_t zeta, t;

  k = 0;
  for(len = 128; len > 0; len >>= 1) {
    for(start = 0; start < MLDSA_N; start = j + len) {
      zeta = zetas[++k];
      for(j = start; j < start + len; ++j) {
        t = mldsa_montgomery_reduce((int64_t)zeta * a[j + len]);
        a[j + len] = a[j] - t;
        a[j] = a[j] + t;
      }
    }
  }
}

/*************************************************
* Name:        mldsa_invntt_tomont
*
* Description: Inverse NTT and multiplication by Montgomery factor 2^32.
*              In-place. No modular reductions after additions or
*              subtractions; input coefficients need to be smaller than
*              MLDSA_Q in absolute value. Output coefficient are smaller than MLDSA_Q in
*              absolute value.
*
* Arguments:   - uint32_t p[MLDSA_N]: input/output coefficient array
**************************************************/
static void mldsa_invntt_tomont(int32_t a[MLDSA_N]) {
  unsigned int start, len, j, k;
  int32_t t, zeta;
  const int32_t f = 41978; // mont^2/256

  k = 256;
  for(len = 1; len < MLDSA_N; len <<= 1) {
    for(start = 0; start < MLDSA_N; start = j + len) {
      zeta = -zetas[--k];
      for(j = start; j < start + len; ++j) {
        t = a[j];
        a[j] = t + a[j + len];
        a[j + len] = t - a[j + len];
        a[j + len] = mldsa_montgomery_reduce((int64_t)zeta * a[j + len]);
      }
    }
  }

  for(j = 0; j < MLDSA_N; ++j) {
    a[j] = mldsa_montgomery_reduce((int64_t)f * a[j]);
  }
}

// ----- mldsa/poly.c -----
#ifdef DBENCH
#define DBENCH_START() uint64_t time = cpucycles()
#define DBENCH_STOP(t) t += cpucycles() - time - timing_overhead
#else
#define DBENCH_START()
#define DBENCH_STOP(t)
#endif

/*************************************************
* Name:        mldsa_poly_reduce
*
* Description: Inplace reduction of all coefficients of polynomial to
*              representative in [-6283008,6283008].
*
* Arguments:   - mldsa_poly *a: pointer to input/output polynomial
**************************************************/
static void mldsa_poly_reduce(mldsa_poly *a) {
  unsigned int i;
  DBENCH_START();

  for(i = 0; i < MLDSA_N; ++i)
    a->coeffs[i] = mldsa_reduce32(a->coeffs[i]);

  DBENCH_STOP(*tred);
}

/*************************************************
* Name:        mldsa_poly_caddq
*
* Description: For all coefficients of in/out polynomial add MLDSA_Q if
*              coefficient is negative.
*
* Arguments:   - mldsa_poly *a: pointer to input/output polynomial
**************************************************/
static void mldsa_poly_caddq(mldsa_poly *a) {
  unsigned int i;
  DBENCH_START();

  for(i = 0; i < MLDSA_N; ++i)
    a->coeffs[i] = mldsa_caddq(a->coeffs[i]);

  DBENCH_STOP(*tred);
}

/*************************************************
* Name:        mldsa_poly_add
*
* Description: Add polynomials. No modular reduction is performed.
*
* Arguments:   - mldsa_poly *c: pointer to output polynomial
*              - const mldsa_poly *a: pointer to first summand
*              - const mldsa_poly *b: pointer to second summand
**************************************************/
static void mldsa_poly_add(mldsa_poly *c, const mldsa_poly *a, const mldsa_poly *b)  {
  unsigned int i;
  DBENCH_START();

  for(i = 0; i < MLDSA_N; ++i)
    c->coeffs[i] = a->coeffs[i] + b->coeffs[i];

  DBENCH_STOP(*tadd);
}

/*************************************************
* Name:        mldsa_poly_sub
*
* Description: Subtract polynomials. No modular reduction is
*              performed.
*
* Arguments:   - mldsa_poly *c: pointer to output polynomial
*              - const mldsa_poly *a: pointer to first input polynomial
*              - const mldsa_poly *b: pointer to second input polynomial to be
*                               subtraced from first input polynomial
**************************************************/
static void mldsa_poly_sub(mldsa_poly *c, const mldsa_poly *a, const mldsa_poly *b) {
  unsigned int i;
  DBENCH_START();

  for(i = 0; i < MLDSA_N; ++i)
    c->coeffs[i] = a->coeffs[i] - b->coeffs[i];

  DBENCH_STOP(*tadd);
}

/*************************************************
* Name:        mldsa_poly_shiftl
*
* Description: Multiply polynomial by 2^MLDSA_D without modular reduction. Assumes
*              input coefficients to be less than 2^{31-MLDSA_D} in absolute value.
*
* Arguments:   - mldsa_poly *a: pointer to input/output polynomial
**************************************************/
static void mldsa_poly_shiftl(mldsa_poly *a) {
  unsigned int i;
  DBENCH_START();

  for(i = 0; i < MLDSA_N; ++i)
    a->coeffs[i] <<= MLDSA_D;

  DBENCH_STOP(*tmul);
}

/*************************************************
* Name:        mldsa_poly_ntt
*
* Description: Inplace forward NTT. Coefficients can grow by
*              8*MLDSA_Q in absolute value.
*
* Arguments:   - mldsa_poly *a: pointer to input/output polynomial
**************************************************/
static void mldsa_poly_ntt(mldsa_poly *a) {
  DBENCH_START();

  mldsa_ntt(a->coeffs);

  DBENCH_STOP(*tmul);
}

/*************************************************
* Name:        mldsa_poly_invntt_tomont
*
* Description: Inplace inverse NTT and multiplication by 2^{32}.
*              Input coefficients need to be less than MLDSA_Q in absolute
*              value and output coefficients are again bounded by MLDSA_Q.
*
* Arguments:   - mldsa_poly *a: pointer to input/output polynomial
**************************************************/
static void mldsa_poly_invntt_tomont(mldsa_poly *a) {
  DBENCH_START();

  mldsa_invntt_tomont(a->coeffs);

  DBENCH_STOP(*tmul);
}

/*************************************************
* Name:        mldsa_poly_pointwise_montgomery
*
* Description: Pointwise multiplication of polynomials in NTT domain
*              representation and multiplication of resulting polynomial
*              by 2^{-32}.
*
* Arguments:   - mldsa_poly *c: pointer to output polynomial
*              - const mldsa_poly *a: pointer to first input polynomial
*              - const mldsa_poly *b: pointer to second input polynomial
**************************************************/
static void mldsa_poly_pointwise_montgomery(mldsa_poly *c, const mldsa_poly *a, const mldsa_poly *b) {
  unsigned int i;
  DBENCH_START();

  for(i = 0; i < MLDSA_N; ++i)
    c->coeffs[i] = mldsa_montgomery_reduce((int64_t)a->coeffs[i] * b->coeffs[i]);

  DBENCH_STOP(*tmul);
}

/*************************************************
* Name:        mldsa_poly_power2round
*
* Description: For all coefficients c of the input polynomial,
*              compute c0, c1 such that c mod MLDSA_Q = c1*2^MLDSA_D + c0
*              with -2^{MLDSA_D-1} < c0 <= 2^{MLDSA_D-1}. Assumes coefficients to be
*              standard representatives.
*
* Arguments:   - mldsa_poly *a1: pointer to output polynomial with coefficients c1
*              - mldsa_poly *a0: pointer to output polynomial with coefficients c0
*              - const mldsa_poly *a: pointer to input polynomial
**************************************************/
static void mldsa_poly_power2round(mldsa_poly *a1, mldsa_poly *a0, const mldsa_poly *a) {
  unsigned int i;
  DBENCH_START();

  for(i = 0; i < MLDSA_N; ++i)
    a1->coeffs[i] = mldsa_power2round(&a0->coeffs[i], a->coeffs[i]);

  DBENCH_STOP(*tround);
}

/*************************************************
* Name:        mldsa_poly_decompose
*
* Description: For all coefficients c of the input polynomial,
*              compute high and low bits c0, c1 such c mod MLDSA_Q = c1*ALPHA + c0
*              with -ALPHA/2 < c0 <= ALPHA/2 except c1 = (MLDSA_Q-1)/ALPHA where we
*              set c1 = 0 and -ALPHA/2 <= c0 = c mod MLDSA_Q - MLDSA_Q < 0.
*              Assumes coefficients to be standard representatives.
*
* Arguments:   - mldsa_poly *a1: pointer to output polynomial with coefficients c1
*              - mldsa_poly *a0: pointer to output polynomial with coefficients c0
*              - const mldsa_poly *a: pointer to input polynomial
**************************************************/
static void mldsa_poly_decompose(mldsa_poly *a1, mldsa_poly *a0, const mldsa_poly *a) {
  unsigned int i;
  DBENCH_START();

  for(i = 0; i < MLDSA_N; ++i)
    a1->coeffs[i] = mldsa_decompose(&a0->coeffs[i], a->coeffs[i]);

  DBENCH_STOP(*tround);
}

/*************************************************
* Name:        mldsa_poly_make_hint
*
* Description: Compute hint polynomial. The coefficients of which indicate
*              whether the low bits of the corresponding coefficient of
*              the input polynomial overflow into the high bits.
*
* Arguments:   - mldsa_poly *h: pointer to output hint polynomial
*              - const mldsa_poly *a0: pointer to low part of input polynomial
*              - const mldsa_poly *a1: pointer to high part of input polynomial
*
* Returns number of 1 bits.
**************************************************/
static unsigned int mldsa_poly_make_hint(mldsa_poly *h, const mldsa_poly *a0, const mldsa_poly *a1) {
  unsigned int i, s = 0;
  DBENCH_START();

  for(i = 0; i < MLDSA_N; ++i) {
    h->coeffs[i] = mldsa_make_hint(a0->coeffs[i], a1->coeffs[i]);
    s += h->coeffs[i];
  }

  DBENCH_STOP(*tround);
  return s;
}

/*************************************************
* Name:        mldsa_poly_use_hint
*
* Description: Use hint polynomial to correct the high bits of a polynomial.
*
* Arguments:   - mldsa_poly *b: pointer to output polynomial with corrected high bits
*              - const mldsa_poly *a: pointer to input polynomial
*              - const mldsa_poly *h: pointer to input hint polynomial
**************************************************/
static void mldsa_poly_use_hint(mldsa_poly *b, const mldsa_poly *a, const mldsa_poly *h) {
  unsigned int i;
  DBENCH_START();

  for(i = 0; i < MLDSA_N; ++i)
    b->coeffs[i] = mldsa_use_hint(a->coeffs[i], h->coeffs[i]);

  DBENCH_STOP(*tround);
}

/*************************************************
* Name:        mldsa_poly_chknorm
*
* Description: Check infinity norm of polynomial against given bound.
*              Assumes input coefficients were reduced by mldsa_reduce32().
*
* Arguments:   - const mldsa_poly *a: pointer to polynomial
*              - int32_t B: norm bound
*
* Returns 0 if norm is strictly smaller than B <= (MLDSA_Q-1)/8 and 1 otherwise.
**************************************************/
static int mldsa_poly_chknorm(const mldsa_poly *a, int32_t B) {
  unsigned int i;
  int32_t t;
  DBENCH_START();

  if(B > (MLDSA_Q-1)/8)
    return 1;

  /* It is ok to leak which coefficient violates the bound since
     the probability for each coefficient is independent of secret
     data but we must not leak the sign of the centralized representative. */
  for(i = 0; i < MLDSA_N; ++i) {
    /* Absolute value */
    t = a->coeffs[i] >> 31;
    t = a->coeffs[i] - (t & 2*a->coeffs[i]);

    if(t >= B) {
      DBENCH_STOP(*tsample);
      return 1;
    }
  }

  DBENCH_STOP(*tsample);
  return 0;
}

/*************************************************
* Name:        mldsa_rej_uniform
*
* Description: Sample uniformly random coefficients in [0, MLDSA_Q-1] by
*              performing rejection sampling on array of random bytes.
*
* Arguments:   - int32_t *a: pointer to output array (allocated)
*              - unsigned int len: number of coefficients to be sampled
*              - const uint8_t *buf: array of random bytes
*              - unsigned int buflen: length of array of random bytes
*
* Returns number of sampled coefficients. Can be smaller than len if not enough
* random bytes were given.
**************************************************/
static unsigned int mldsa_rej_uniform(int32_t *a,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen)
{
  unsigned int ctr, pos;
  uint32_t t;
  DBENCH_START();

  ctr = pos = 0;
  while(ctr < len && pos + 3 <= buflen) {
    t  = buf[pos++];
    t |= (uint32_t)buf[pos++] << 8;
    t |= (uint32_t)buf[pos++] << 16;
    t &= 0x7FFFFF;

    if(t < MLDSA_Q)
      a[ctr++] = t;
  }

  DBENCH_STOP(*tsample);
  return ctr;
}

/*************************************************
* Name:        mldsa_poly_uniform
*
* Description: Sample polynomial with uniformly random coefficients
*              in [0,MLDSA_Q-1] by performing rejection sampling on the
*              output stream of SHAKE128(seed|nonce)
*
* Arguments:   - mldsa_poly *a: pointer to output polynomial
*              - const uint8_t seed[]: byte array with seed of length MLDSA_SEEDBYTES
*              - uint16_t nonce: 2-byte nonce
**************************************************/
#define POLY_UNIFORM_NBLOCKS ((768 + STREAM128_BLOCKBYTES - 1)/STREAM128_BLOCKBYTES)
static void mldsa_poly_uniform(mldsa_poly *a,
                  const uint8_t seed[MLDSA_SEEDBYTES],
                  uint16_t nonce)
{
  unsigned int i, ctr, off;
  unsigned int buflen = POLY_UNIFORM_NBLOCKS*STREAM128_BLOCKBYTES;
  uint8_t buf[POLY_UNIFORM_NBLOCKS*STREAM128_BLOCKBYTES + 2];
  mldsa_stream128_state state;

  stream128_init(&state, seed, nonce);
  stream128_squeezeblocks(buf, POLY_UNIFORM_NBLOCKS, &state);

  ctr = mldsa_rej_uniform(a->coeffs, MLDSA_N, buf, buflen);

  while(ctr < MLDSA_N) {
    off = buflen % 3;
    for(i = 0; i < off; ++i)
      buf[i] = buf[buflen - off + i];

    stream128_squeezeblocks(buf + off, 1, &state);
    buflen = STREAM128_BLOCKBYTES + off;
    ctr += mldsa_rej_uniform(a->coeffs + ctr, MLDSA_N - ctr, buf, buflen);
  }
}

/*************************************************
* Name:        rej_eta
*
* Description: Sample uniformly random coefficients in [-MLDSA_ETA, MLDSA_ETA] by
*              performing rejection sampling on array of random bytes.
*
* Arguments:   - int32_t *a: pointer to output array (allocated)
*              - unsigned int len: number of coefficients to be sampled
*              - const uint8_t *buf: array of random bytes
*              - unsigned int buflen: length of array of random bytes
*
* Returns number of sampled coefficients. Can be smaller than len if not enough
* random bytes were given.
**************************************************/
static unsigned int rej_eta(int32_t *a,
                            unsigned int len,
                            const uint8_t *buf,
                            unsigned int buflen)
{
  unsigned int ctr, pos;
  uint32_t t0, t1;
  DBENCH_START();

  ctr = pos = 0;
  while(ctr < len && pos < buflen) {
    t0 = buf[pos] & 0x0F;
    t1 = buf[pos++] >> 4;

#if MLDSA_ETA == 2
    if(t0 < 15) {
      t0 = t0 - (205*t0 >> 10)*5;
      a[ctr++] = 2 - t0;
    }
    if(t1 < 15 && ctr < len) {
      t1 = t1 - (205*t1 >> 10)*5;
      a[ctr++] = 2 - t1;
    }
#elif MLDSA_ETA == 4
    if(t0 < 9)
      a[ctr++] = 4 - t0;
    if(t1 < 9 && ctr < len)
      a[ctr++] = 4 - t1;
#endif
  }

  DBENCH_STOP(*tsample);
  return ctr;
}

/*************************************************
* Name:        mldsa_poly_uniform_eta
*
* Description: Sample polynomial with uniformly random coefficients
*              in [-MLDSA_ETA,MLDSA_ETA] by performing rejection sampling on the
*              output stream from SHAKE256(seed|nonce)
*
* Arguments:   - mldsa_poly *a: pointer to output polynomial
*              - const uint8_t seed[]: byte array with seed of length MLDSA_CRHBYTES
*              - uint16_t nonce: 2-byte nonce
**************************************************/
#if MLDSA_ETA == 2
#define POLY_UNIFORM_ETA_NBLOCKS ((136 + STREAM256_BLOCKBYTES - 1)/STREAM256_BLOCKBYTES)
#elif MLDSA_ETA == 4
#define POLY_UNIFORM_ETA_NBLOCKS ((227 + STREAM256_BLOCKBYTES - 1)/STREAM256_BLOCKBYTES)
#endif
static void mldsa_poly_uniform_eta(mldsa_poly *a,
                      const uint8_t seed[MLDSA_CRHBYTES],
                      uint16_t nonce)
{
  unsigned int ctr;
  unsigned int buflen = POLY_UNIFORM_ETA_NBLOCKS*STREAM256_BLOCKBYTES;
  uint8_t buf[POLY_UNIFORM_ETA_NBLOCKS*STREAM256_BLOCKBYTES];
  mldsa_stream256_state state;

  stream256_init(&state, seed, nonce);
  stream256_squeezeblocks(buf, POLY_UNIFORM_ETA_NBLOCKS, &state);

  ctr = rej_eta(a->coeffs, MLDSA_N, buf, buflen);

  while(ctr < MLDSA_N) {
    stream256_squeezeblocks(buf, 1, &state);
    ctr += rej_eta(a->coeffs + ctr, MLDSA_N - ctr, buf, STREAM256_BLOCKBYTES);
  }
}

/*************************************************
* Name:        poly_uniform_gamma1m1
*
* Description: Sample polynomial with uniformly random coefficients
*              in [-(MLDSA_GAMMA1 - 1), MLDSA_GAMMA1] by unpacking output stream
*              of SHAKE256(seed|nonce)
*
* Arguments:   - mldsa_poly *a: pointer to output polynomial
*              - const uint8_t seed[]: byte array with seed of length MLDSA_CRHBYTES
*              - uint16_t nonce: 16-bit nonce
**************************************************/
#define POLY_UNIFORM_GAMMA1_NBLOCKS ((MLDSA_POLYZ_PACKEDBYTES + STREAM256_BLOCKBYTES - 1)/STREAM256_BLOCKBYTES)
static void mldsa_poly_uniform_gamma1(mldsa_poly *a,
                         const uint8_t seed[MLDSA_CRHBYTES],
                         uint16_t nonce)
{
  uint8_t buf[POLY_UNIFORM_GAMMA1_NBLOCKS*STREAM256_BLOCKBYTES];
  mldsa_stream256_state state;

  stream256_init(&state, seed, nonce);
  stream256_squeezeblocks(buf, POLY_UNIFORM_GAMMA1_NBLOCKS, &state);
  mldsa_polyz_unpack(a, buf);
}

/*************************************************
* Name:        challenge
*
* Description: Implementation of H. Samples polynomial with MLDSA_TAU nonzero
*              coefficients in {-1,1} using the output stream of
*              SHAKE256(seed).
*
* Arguments:   - mldsa_poly *c: pointer to output polynomial
*              - const uint8_t mu[]: byte array containing seed of length MLDSA_CTILDEBYTES
**************************************************/
static void mldsa_poly_challenge(mldsa_poly *c, const uint8_t seed[MLDSA_CTILDEBYTES]) {
  unsigned int i, b, pos;
  uint64_t signs;
  uint8_t buf[SHAKE256_RATE];
  keccak_state state;

  shake256_init(&state);
  shake256_absorb(&state, seed, MLDSA_CTILDEBYTES);
  shake256_finalize(&state);
  shake256_squeezeblocks(buf, 1, &state);

  signs = 0;
  for(i = 0; i < 8; ++i)
    signs |= (uint64_t)buf[i] << 8*i;
  pos = 8;

  for(i = 0; i < MLDSA_N; ++i)
    c->coeffs[i] = 0;
  for(i = MLDSA_N-MLDSA_TAU; i < MLDSA_N; ++i) {
    do {
      if(pos >= SHAKE256_RATE) {
        shake256_squeezeblocks(buf, 1, &state);
        pos = 0;
      }

      b = buf[pos++];
    } while(b > i);

    c->coeffs[i] = c->coeffs[b];
    c->coeffs[b] = 1 - 2*(signs & 1);
    signs >>= 1;
  }
}

/*************************************************
* Name:        mldsa_polyeta_pack
*
* Description: Bit-pack polynomial with coefficients in [-MLDSA_ETA,MLDSA_ETA].
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                            MLDSA_POLYETA_PACKEDBYTES bytes
*              - const mldsa_poly *a: pointer to input polynomial
**************************************************/
static void mldsa_polyeta_pack(uint8_t *r, const mldsa_poly *a) {
  unsigned int i;
  uint8_t t[8];
  DBENCH_START();

#if MLDSA_ETA == 2
  for(i = 0; i < MLDSA_N/8; ++i) {
    t[0] = MLDSA_ETA - a->coeffs[8*i+0];
    t[1] = MLDSA_ETA - a->coeffs[8*i+1];
    t[2] = MLDSA_ETA - a->coeffs[8*i+2];
    t[3] = MLDSA_ETA - a->coeffs[8*i+3];
    t[4] = MLDSA_ETA - a->coeffs[8*i+4];
    t[5] = MLDSA_ETA - a->coeffs[8*i+5];
    t[6] = MLDSA_ETA - a->coeffs[8*i+6];
    t[7] = MLDSA_ETA - a->coeffs[8*i+7];

    r[3*i+0]  = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
    r[3*i+1]  = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
    r[3*i+2]  = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
  }
#elif MLDSA_ETA == 4
  for(i = 0; i < MLDSA_N/2; ++i) {
    t[0] = MLDSA_ETA - a->coeffs[2*i+0];
    t[1] = MLDSA_ETA - a->coeffs[2*i+1];
    r[i] = t[0] | (t[1] << 4);
  }
#endif

  DBENCH_STOP(*tpack);
}

/*************************************************
* Name:        mldsa_polyeta_unpack
*
* Description: Unpack polynomial with coefficients in [-MLDSA_ETA,MLDSA_ETA].
*
* Arguments:   - mldsa_poly *r: pointer to output polynomial
*              - const uint8_t *a: byte array with bit-packed polynomial
**************************************************/
static void mldsa_polyeta_unpack(mldsa_poly *r, const uint8_t *a) {
  unsigned int i;
  DBENCH_START();

#if MLDSA_ETA == 2
  for(i = 0; i < MLDSA_N/8; ++i) {
    r->coeffs[8*i+0] =  (a[3*i+0] >> 0) & 7;
    r->coeffs[8*i+1] =  (a[3*i+0] >> 3) & 7;
    r->coeffs[8*i+2] = ((a[3*i+0] >> 6) | (a[3*i+1] << 2)) & 7;
    r->coeffs[8*i+3] =  (a[3*i+1] >> 1) & 7;
    r->coeffs[8*i+4] =  (a[3*i+1] >> 4) & 7;
    r->coeffs[8*i+5] = ((a[3*i+1] >> 7) | (a[3*i+2] << 1)) & 7;
    r->coeffs[8*i+6] =  (a[3*i+2] >> 2) & 7;
    r->coeffs[8*i+7] =  (a[3*i+2] >> 5) & 7;

    r->coeffs[8*i+0] = MLDSA_ETA - r->coeffs[8*i+0];
    r->coeffs[8*i+1] = MLDSA_ETA - r->coeffs[8*i+1];
    r->coeffs[8*i+2] = MLDSA_ETA - r->coeffs[8*i+2];
    r->coeffs[8*i+3] = MLDSA_ETA - r->coeffs[8*i+3];
    r->coeffs[8*i+4] = MLDSA_ETA - r->coeffs[8*i+4];
    r->coeffs[8*i+5] = MLDSA_ETA - r->coeffs[8*i+5];
    r->coeffs[8*i+6] = MLDSA_ETA - r->coeffs[8*i+6];
    r->coeffs[8*i+7] = MLDSA_ETA - r->coeffs[8*i+7];
  }
#elif MLDSA_ETA == 4
  for(i = 0; i < MLDSA_N/2; ++i) {
    r->coeffs[2*i+0] = a[i] & 0x0F;
    r->coeffs[2*i+1] = a[i] >> 4;
    r->coeffs[2*i+0] = MLDSA_ETA - r->coeffs[2*i+0];
    r->coeffs[2*i+1] = MLDSA_ETA - r->coeffs[2*i+1];
  }
#endif

  DBENCH_STOP(*tpack);
}

/*************************************************
* Name:        mldsa_polyt1_pack
*
* Description: Bit-pack polynomial t1 with coefficients fitting in 10 bits.
*              Input coefficients are assumed to be standard representatives.
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                            MLDSA_POLYT1_PACKEDBYTES bytes
*              - const mldsa_poly *a: pointer to input polynomial
**************************************************/
static void mldsa_polyt1_pack(uint8_t *r, const mldsa_poly *a) {
  unsigned int i;
  DBENCH_START();

  for(i = 0; i < MLDSA_N/4; ++i) {
    r[5*i+0] = (a->coeffs[4*i+0] >> 0);
    r[5*i+1] = (a->coeffs[4*i+0] >> 8) | (a->coeffs[4*i+1] << 2);
    r[5*i+2] = (a->coeffs[4*i+1] >> 6) | (a->coeffs[4*i+2] << 4);
    r[5*i+3] = (a->coeffs[4*i+2] >> 4) | (a->coeffs[4*i+3] << 6);
    r[5*i+4] = (a->coeffs[4*i+3] >> 2);
  }

  DBENCH_STOP(*tpack);
}

/*************************************************
* Name:        mldsa_polyt1_unpack
*
* Description: Unpack polynomial t1 with 10-bit coefficients.
*              Output coefficients are standard representatives.
*
* Arguments:   - mldsa_poly *r: pointer to output polynomial
*              - const uint8_t *a: byte array with bit-packed polynomial
**************************************************/
static void mldsa_polyt1_unpack(mldsa_poly *r, const uint8_t *a) {
  unsigned int i;
  DBENCH_START();

  for(i = 0; i < MLDSA_N/4; ++i) {
    r->coeffs[4*i+0] = ((a[5*i+0] >> 0) | ((uint32_t)a[5*i+1] << 8)) & 0x3FF;
    r->coeffs[4*i+1] = ((a[5*i+1] >> 2) | ((uint32_t)a[5*i+2] << 6)) & 0x3FF;
    r->coeffs[4*i+2] = ((a[5*i+2] >> 4) | ((uint32_t)a[5*i+3] << 4)) & 0x3FF;
    r->coeffs[4*i+3] = ((a[5*i+3] >> 6) | ((uint32_t)a[5*i+4] << 2)) & 0x3FF;
  }

  DBENCH_STOP(*tpack);
}

/*************************************************
* Name:        mldsa_polyt0_pack
*
* Description: Bit-pack polynomial t0 with coefficients in ]-2^{MLDSA_D-1}, 2^{MLDSA_D-1}].
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                            MLDSA_POLYT0_PACKEDBYTES bytes
*              - const mldsa_poly *a: pointer to input polynomial
**************************************************/
static void mldsa_polyt0_pack(uint8_t *r, const mldsa_poly *a) {
  unsigned int i;
  uint32_t t[8];
  DBENCH_START();

  for(i = 0; i < MLDSA_N/8; ++i) {
    t[0] = (1 << (MLDSA_D-1)) - a->coeffs[8*i+0];
    t[1] = (1 << (MLDSA_D-1)) - a->coeffs[8*i+1];
    t[2] = (1 << (MLDSA_D-1)) - a->coeffs[8*i+2];
    t[3] = (1 << (MLDSA_D-1)) - a->coeffs[8*i+3];
    t[4] = (1 << (MLDSA_D-1)) - a->coeffs[8*i+4];
    t[5] = (1 << (MLDSA_D-1)) - a->coeffs[8*i+5];
    t[6] = (1 << (MLDSA_D-1)) - a->coeffs[8*i+6];
    t[7] = (1 << (MLDSA_D-1)) - a->coeffs[8*i+7];

    r[13*i+ 0]  =  t[0];
    r[13*i+ 1]  =  t[0] >>  8;
    r[13*i+ 1] |=  t[1] <<  5;
    r[13*i+ 2]  =  t[1] >>  3;
    r[13*i+ 3]  =  t[1] >> 11;
    r[13*i+ 3] |=  t[2] <<  2;
    r[13*i+ 4]  =  t[2] >>  6;
    r[13*i+ 4] |=  t[3] <<  7;
    r[13*i+ 5]  =  t[3] >>  1;
    r[13*i+ 6]  =  t[3] >>  9;
    r[13*i+ 6] |=  t[4] <<  4;
    r[13*i+ 7]  =  t[4] >>  4;
    r[13*i+ 8]  =  t[4] >> 12;
    r[13*i+ 8] |=  t[5] <<  1;
    r[13*i+ 9]  =  t[5] >>  7;
    r[13*i+ 9] |=  t[6] <<  6;
    r[13*i+10]  =  t[6] >>  2;
    r[13*i+11]  =  t[6] >> 10;
    r[13*i+11] |=  t[7] <<  3;
    r[13*i+12]  =  t[7] >>  5;
  }

  DBENCH_STOP(*tpack);
}

/*************************************************
* Name:        mldsa_polyt0_unpack
*
* Description: Unpack polynomial t0 with coefficients in ]-2^{MLDSA_D-1}, 2^{MLDSA_D-1}].
*
* Arguments:   - mldsa_poly *r: pointer to output polynomial
*              - const uint8_t *a: byte array with bit-packed polynomial
**************************************************/
static void mldsa_polyt0_unpack(mldsa_poly *r, const uint8_t *a) {
  unsigned int i;
  DBENCH_START();

  for(i = 0; i < MLDSA_N/8; ++i) {
    r->coeffs[8*i+0]  = a[13*i+0];
    r->coeffs[8*i+0] |= (uint32_t)a[13*i+1] << 8;
    r->coeffs[8*i+0] &= 0x1FFF;

    r->coeffs[8*i+1]  = a[13*i+1] >> 5;
    r->coeffs[8*i+1] |= (uint32_t)a[13*i+2] << 3;
    r->coeffs[8*i+1] |= (uint32_t)a[13*i+3] << 11;
    r->coeffs[8*i+1] &= 0x1FFF;

    r->coeffs[8*i+2]  = a[13*i+3] >> 2;
    r->coeffs[8*i+2] |= (uint32_t)a[13*i+4] << 6;
    r->coeffs[8*i+2] &= 0x1FFF;

    r->coeffs[8*i+3]  = a[13*i+4] >> 7;
    r->coeffs[8*i+3] |= (uint32_t)a[13*i+5] << 1;
    r->coeffs[8*i+3] |= (uint32_t)a[13*i+6] << 9;
    r->coeffs[8*i+3] &= 0x1FFF;

    r->coeffs[8*i+4]  = a[13*i+6] >> 4;
    r->coeffs[8*i+4] |= (uint32_t)a[13*i+7] << 4;
    r->coeffs[8*i+4] |= (uint32_t)a[13*i+8] << 12;
    r->coeffs[8*i+4] &= 0x1FFF;

    r->coeffs[8*i+5]  = a[13*i+8] >> 1;
    r->coeffs[8*i+5] |= (uint32_t)a[13*i+9] << 7;
    r->coeffs[8*i+5] &= 0x1FFF;

    r->coeffs[8*i+6]  = a[13*i+9] >> 6;
    r->coeffs[8*i+6] |= (uint32_t)a[13*i+10] << 2;
    r->coeffs[8*i+6] |= (uint32_t)a[13*i+11] << 10;
    r->coeffs[8*i+6] &= 0x1FFF;

    r->coeffs[8*i+7]  = a[13*i+11] >> 3;
    r->coeffs[8*i+7] |= (uint32_t)a[13*i+12] << 5;
    r->coeffs[8*i+7] &= 0x1FFF;

    r->coeffs[8*i+0] = (1 << (MLDSA_D-1)) - r->coeffs[8*i+0];
    r->coeffs[8*i+1] = (1 << (MLDSA_D-1)) - r->coeffs[8*i+1];
    r->coeffs[8*i+2] = (1 << (MLDSA_D-1)) - r->coeffs[8*i+2];
    r->coeffs[8*i+3] = (1 << (MLDSA_D-1)) - r->coeffs[8*i+3];
    r->coeffs[8*i+4] = (1 << (MLDSA_D-1)) - r->coeffs[8*i+4];
    r->coeffs[8*i+5] = (1 << (MLDSA_D-1)) - r->coeffs[8*i+5];
    r->coeffs[8*i+6] = (1 << (MLDSA_D-1)) - r->coeffs[8*i+6];
    r->coeffs[8*i+7] = (1 << (MLDSA_D-1)) - r->coeffs[8*i+7];
  }

  DBENCH_STOP(*tpack);
}

/*************************************************
* Name:        mldsa_polyz_pack
*
* Description: Bit-pack polynomial with coefficients
*              in [-(MLDSA_GAMMA1 - 1), MLDSA_GAMMA1].
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                            MLDSA_POLYZ_PACKEDBYTES bytes
*              - const mldsa_poly *a: pointer to input polynomial
**************************************************/
static void mldsa_polyz_pack(uint8_t *r, const mldsa_poly *a) {
  unsigned int i;
  uint32_t t[4];
  DBENCH_START();

#if MLDSA_GAMMA1 == (1 << 17)
  for(i = 0; i < MLDSA_N/4; ++i) {
    t[0] = MLDSA_GAMMA1 - a->coeffs[4*i+0];
    t[1] = MLDSA_GAMMA1 - a->coeffs[4*i+1];
    t[2] = MLDSA_GAMMA1 - a->coeffs[4*i+2];
    t[3] = MLDSA_GAMMA1 - a->coeffs[4*i+3];

    r[9*i+0]  = t[0];
    r[9*i+1]  = t[0] >> 8;
    r[9*i+2]  = t[0] >> 16;
    r[9*i+2] |= t[1] << 2;
    r[9*i+3]  = t[1] >> 6;
    r[9*i+4]  = t[1] >> 14;
    r[9*i+4] |= t[2] << 4;
    r[9*i+5]  = t[2] >> 4;
    r[9*i+6]  = t[2] >> 12;
    r[9*i+6] |= t[3] << 6;
    r[9*i+7]  = t[3] >> 2;
    r[9*i+8]  = t[3] >> 10;
  }
#elif MLDSA_GAMMA1 == (1 << 19)
  for(i = 0; i < MLDSA_N/2; ++i) {
    t[0] = MLDSA_GAMMA1 - a->coeffs[2*i+0];
    t[1] = MLDSA_GAMMA1 - a->coeffs[2*i+1];

    r[5*i+0]  = t[0];
    r[5*i+1]  = t[0] >> 8;
    r[5*i+2]  = t[0] >> 16;
    r[5*i+2] |= t[1] << 4;
    r[5*i+3]  = t[1] >> 4;
    r[5*i+4]  = t[1] >> 12;
  }
#endif

  DBENCH_STOP(*tpack);
}

/*************************************************
* Name:        mldsa_polyz_unpack
*
* Description: Unpack polynomial z with coefficients
*              in [-(MLDSA_GAMMA1 - 1), MLDSA_GAMMA1].
*
* Arguments:   - mldsa_poly *r: pointer to output polynomial
*              - const uint8_t *a: byte array with bit-packed polynomial
**************************************************/
static void mldsa_polyz_unpack(mldsa_poly *r, const uint8_t *a) {
  unsigned int i;
  DBENCH_START();

#if MLDSA_GAMMA1 == (1 << 17)
  for(i = 0; i < MLDSA_N/4; ++i) {
    r->coeffs[4*i+0]  = a[9*i+0];
    r->coeffs[4*i+0] |= (uint32_t)a[9*i+1] << 8;
    r->coeffs[4*i+0] |= (uint32_t)a[9*i+2] << 16;
    r->coeffs[4*i+0] &= 0x3FFFF;

    r->coeffs[4*i+1]  = a[9*i+2] >> 2;
    r->coeffs[4*i+1] |= (uint32_t)a[9*i+3] << 6;
    r->coeffs[4*i+1] |= (uint32_t)a[9*i+4] << 14;
    r->coeffs[4*i+1] &= 0x3FFFF;

    r->coeffs[4*i+2]  = a[9*i+4] >> 4;
    r->coeffs[4*i+2] |= (uint32_t)a[9*i+5] << 4;
    r->coeffs[4*i+2] |= (uint32_t)a[9*i+6] << 12;
    r->coeffs[4*i+2] &= 0x3FFFF;

    r->coeffs[4*i+3]  = a[9*i+6] >> 6;
    r->coeffs[4*i+3] |= (uint32_t)a[9*i+7] << 2;
    r->coeffs[4*i+3] |= (uint32_t)a[9*i+8] << 10;
    r->coeffs[4*i+3] &= 0x3FFFF;

    r->coeffs[4*i+0] = MLDSA_GAMMA1 - r->coeffs[4*i+0];
    r->coeffs[4*i+1] = MLDSA_GAMMA1 - r->coeffs[4*i+1];
    r->coeffs[4*i+2] = MLDSA_GAMMA1 - r->coeffs[4*i+2];
    r->coeffs[4*i+3] = MLDSA_GAMMA1 - r->coeffs[4*i+3];
  }
#elif MLDSA_GAMMA1 == (1 << 19)
  for(i = 0; i < MLDSA_N/2; ++i) {
    r->coeffs[2*i+0]  = a[5*i+0];
    r->coeffs[2*i+0] |= (uint32_t)a[5*i+1] << 8;
    r->coeffs[2*i+0] |= (uint32_t)a[5*i+2] << 16;
    r->coeffs[2*i+0] &= 0xFFFFF;

    r->coeffs[2*i+1]  = a[5*i+2] >> 4;
    r->coeffs[2*i+1] |= (uint32_t)a[5*i+3] << 4;
    r->coeffs[2*i+1] |= (uint32_t)a[5*i+4] << 12;
    /* r->coeffs[2*i+1] &= 0xFFFFF; */ /* No effect, since we're anyway at 20 bits */

    r->coeffs[2*i+0] = MLDSA_GAMMA1 - r->coeffs[2*i+0];
    r->coeffs[2*i+1] = MLDSA_GAMMA1 - r->coeffs[2*i+1];
  }
#endif

  DBENCH_STOP(*tpack);
}

/*************************************************
* Name:        mldsa_polyw1_pack
*
* Description: Bit-pack polynomial w1 with coefficients in [0,15] or [0,43].
*              Input coefficients are assumed to be standard representatives.
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                            MLDSA_POLYW1_PACKEDBYTES bytes
*              - const mldsa_poly *a: pointer to input polynomial
**************************************************/
static void mldsa_polyw1_pack(uint8_t *r, const mldsa_poly *a) {
  unsigned int i;
  DBENCH_START();

#if MLDSA_GAMMA2 == (MLDSA_Q-1)/88
  for(i = 0; i < MLDSA_N/4; ++i) {
    r[3*i+0]  = a->coeffs[4*i+0];
    r[3*i+0] |= a->coeffs[4*i+1] << 6;
    r[3*i+1]  = a->coeffs[4*i+1] >> 2;
    r[3*i+1] |= a->coeffs[4*i+2] << 4;
    r[3*i+2]  = a->coeffs[4*i+2] >> 4;
    r[3*i+2] |= a->coeffs[4*i+3] << 2;
  }
#elif MLDSA_GAMMA2 == (MLDSA_Q-1)/32
  for(i = 0; i < MLDSA_N/2; ++i)
    r[i] = a->coeffs[2*i+0] | (a->coeffs[2*i+1] << 4);
#endif

  DBENCH_STOP(*tpack);
}

// ----- mldsa/polyvec.c -----
/*************************************************
* Name:        expand_mat
*
* Description: Implementation of ExpandA. Generates matrix A with uniformly
*              random coefficients a_{i,j} by performing rejection
*              sampling on the output stream of SHAKE128(rho|j|i)
*
* Arguments:   - mldsa_polyvecl mat[MLDSA_K]: output matrix
*              - const uint8_t rho[]: byte array containing seed rho
**************************************************/
static void mldsa_polyvec_matrix_expand(mldsa_polyvecl mat[MLDSA_K], const uint8_t rho[MLDSA_SEEDBYTES]) {
  unsigned int i, j;

  for(i = 0; i < MLDSA_K; ++i)
    for(j = 0; j < MLDSA_L; ++j)
      mldsa_poly_uniform(&mat[i].vec[j], rho, (i << 8) + j);
}

static void mldsa_polyvec_matrix_pointwise_montgomery(mldsa_polyveck *t, const mldsa_polyvecl mat[MLDSA_K], const mldsa_polyvecl *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_polyvecl_pointwise_acc_montgomery(&t->vec[i], &mat[i], v);
}

/**************************************************************/
/************ Vectors of polynomials of length MLDSA_L **************/
/**************************************************************/

static void mldsa_polyvecl_uniform_eta(mldsa_polyvecl *v, const uint8_t seed[MLDSA_CRHBYTES], uint16_t nonce) {
  unsigned int i;

  for(i = 0; i < MLDSA_L; ++i)
    mldsa_poly_uniform_eta(&v->vec[i], seed, nonce++);
}

static void mldsa_polyvecl_uniform_gamma1(mldsa_polyvecl *v, const uint8_t seed[MLDSA_CRHBYTES], uint16_t nonce) {
  unsigned int i;

  for(i = 0; i < MLDSA_L; ++i)
    mldsa_poly_uniform_gamma1(&v->vec[i], seed, MLDSA_L*nonce + i);
}

static void mldsa_polyvecl_reduce(mldsa_polyvecl *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_L; ++i)
    mldsa_poly_reduce(&v->vec[i]);
}

/*************************************************
* Name:        mldsa_polyvecl_add
*
* Description: Add vectors of polynomials of length MLDSA_L.
*              No modular reduction is performed.
*
* Arguments:   - mldsa_polyvecl *w: pointer to output vector
*              - const mldsa_polyvecl *u: pointer to first summand
*              - const mldsa_polyvecl *v: pointer to second summand
**************************************************/
static void mldsa_polyvecl_add(mldsa_polyvecl *w, const mldsa_polyvecl *u, const mldsa_polyvecl *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_L; ++i)
    mldsa_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        mldsa_polyvecl_ntt
*
* Description: Forward NTT of all polynomials in vector of length MLDSA_L. Output
*              coefficients can be up to 16*MLDSA_Q larger than input coefficients.
*
* Arguments:   - mldsa_polyvecl *v: pointer to input/output vector
**************************************************/
static void mldsa_polyvecl_ntt(mldsa_polyvecl *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_L; ++i)
    mldsa_poly_ntt(&v->vec[i]);
}

static void mldsa_polyvecl_invntt_tomont(mldsa_polyvecl *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_L; ++i)
    mldsa_poly_invntt_tomont(&v->vec[i]);
}

static void mldsa_polyvecl_pointwise_poly_montgomery(mldsa_polyvecl *r, const mldsa_poly *a, const mldsa_polyvecl *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_L; ++i)
    mldsa_poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}

/*************************************************
* Name:        mldsa_polyvecl_pointwise_acc_montgomery
*
* Description: Pointwise multiply vectors of polynomials of length MLDSA_L, multiply
*              resulting vector by 2^{-32} and add (accumulate) polynomials
*              in it. Input/output vectors are in NTT domain representation.
*
* Arguments:   - mldsa_poly *w: output polynomial
*              - const mldsa_polyvecl *u: pointer to first input vector
*              - const mldsa_polyvecl *v: pointer to second input vector
**************************************************/
static void mldsa_polyvecl_pointwise_acc_montgomery(mldsa_poly *w,
                                       const mldsa_polyvecl *u,
                                       const mldsa_polyvecl *v)
{
  unsigned int i;
  mldsa_poly t;

  mldsa_poly_pointwise_montgomery(w, &u->vec[0], &v->vec[0]);
  for(i = 1; i < MLDSA_L; ++i) {
    mldsa_poly_pointwise_montgomery(&t, &u->vec[i], &v->vec[i]);
    mldsa_poly_add(w, w, &t);
  }
}

/*************************************************
* Name:        mldsa_polyvecl_chknorm
*
* Description: Check infinity norm of polynomials in vector of length MLDSA_L.
*              Assumes input mldsa_polyvecl to be reduced by mldsa_polyvecl_reduce().
*
* Arguments:   - const mldsa_polyvecl *v: pointer to vector
*              - int32_t B: norm bound
*
* Returns 0 if norm of all polynomials is strictly smaller than B <= (MLDSA_Q-1)/8
* and 1 otherwise.
**************************************************/
static int mldsa_polyvecl_chknorm(const mldsa_polyvecl *v, int32_t bound)  {
  unsigned int i;

  for(i = 0; i < MLDSA_L; ++i)
    if(mldsa_poly_chknorm(&v->vec[i], bound))
      return 1;

  return 0;
}

/**************************************************************/
/************ Vectors of polynomials of length MLDSA_K **************/
/**************************************************************/

static void mldsa_polyveck_uniform_eta(mldsa_polyveck *v, const uint8_t seed[MLDSA_CRHBYTES], uint16_t nonce) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_poly_uniform_eta(&v->vec[i], seed, nonce++);
}

/*************************************************
* Name:        mldsa_polyveck_reduce
*
* Description: Reduce coefficients of polynomials in vector of length MLDSA_K
*              to representatives in [-6283008,6283008].
*
* Arguments:   - mldsa_polyveck *v: pointer to input/output vector
**************************************************/
static void mldsa_polyveck_reduce(mldsa_polyveck *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_poly_reduce(&v->vec[i]);
}

/*************************************************
* Name:        mldsa_polyveck_caddq
*
* Description: For all coefficients of polynomials in vector of length MLDSA_K
*              add MLDSA_Q if coefficient is negative.
*
* Arguments:   - mldsa_polyveck *v: pointer to input/output vector
**************************************************/
static void mldsa_polyveck_caddq(mldsa_polyveck *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_poly_caddq(&v->vec[i]);
}

/*************************************************
* Name:        mldsa_polyveck_add
*
* Description: Add vectors of polynomials of length MLDSA_K.
*              No modular reduction is performed.
*
* Arguments:   - mldsa_polyveck *w: pointer to output vector
*              - const mldsa_polyveck *u: pointer to first summand
*              - const mldsa_polyveck *v: pointer to second summand
**************************************************/
static void mldsa_polyveck_add(mldsa_polyveck *w, const mldsa_polyveck *u, const mldsa_polyveck *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        mldsa_polyveck_sub
*
* Description: Subtract vectors of polynomials of length MLDSA_K.
*              No modular reduction is performed.
*
* Arguments:   - mldsa_polyveck *w: pointer to output vector
*              - const mldsa_polyveck *u: pointer to first input vector
*              - const mldsa_polyveck *v: pointer to second input vector to be
*                                   subtracted from first input vector
**************************************************/
static void mldsa_polyveck_sub(mldsa_polyveck *w, const mldsa_polyveck *u, const mldsa_polyveck *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        mldsa_polyveck_shiftl
*
* Description: Multiply vector of polynomials of Length MLDSA_K by 2^MLDSA_D without modular
*              reduction. Assumes input coefficients to be less than 2^{31-MLDSA_D}.
*
* Arguments:   - mldsa_polyveck *v: pointer to input/output vector
**************************************************/
static void mldsa_polyveck_shiftl(mldsa_polyveck *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_poly_shiftl(&v->vec[i]);
}

/*************************************************
* Name:        mldsa_polyveck_ntt
*
* Description: Forward NTT of all polynomials in vector of length MLDSA_K. Output
*              coefficients can be up to 16*MLDSA_Q larger than input coefficients.
*
* Arguments:   - mldsa_polyveck *v: pointer to input/output vector
**************************************************/
static void mldsa_polyveck_ntt(mldsa_polyveck *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_poly_ntt(&v->vec[i]);
}

/*************************************************
* Name:        mldsa_polyveck_invntt_tomont
*
* Description: Inverse NTT and multiplication by 2^{32} of polynomials
*              in vector of length MLDSA_K. Input coefficients need to be less
*              than 2*MLDSA_Q.
*
* Arguments:   - mldsa_polyveck *v: pointer to input/output vector
**************************************************/
static void mldsa_polyveck_invntt_tomont(mldsa_polyveck *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_poly_invntt_tomont(&v->vec[i]);
}

static void mldsa_polyveck_pointwise_poly_montgomery(mldsa_polyveck *r, const mldsa_poly *a, const mldsa_polyveck *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}


/*************************************************
* Name:        mldsa_polyveck_chknorm
*
* Description: Check infinity norm of polynomials in vector of length MLDSA_K.
*              Assumes input mldsa_polyveck to be reduced by mldsa_polyveck_reduce().
*
* Arguments:   - const mldsa_polyveck *v: pointer to vector
*              - int32_t B: norm bound
*
* Returns 0 if norm of all polynomials are strictly smaller than B <= (MLDSA_Q-1)/8
* and 1 otherwise.
**************************************************/
static int mldsa_polyveck_chknorm(const mldsa_polyveck *v, int32_t bound) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    if(mldsa_poly_chknorm(&v->vec[i], bound))
      return 1;

  return 0;
}

/*************************************************
* Name:        mldsa_polyveck_power2round
*
* Description: For all coefficients a of polynomials in vector of length MLDSA_K,
*              compute a0, a1 such that a mod^+ MLDSA_Q = a1*2^MLDSA_D + a0
*              with -2^{MLDSA_D-1} < a0 <= 2^{MLDSA_D-1}. Assumes coefficients to be
*              standard representatives.
*
* Arguments:   - mldsa_polyveck *v1: pointer to output vector of polynomials with
*                              coefficients a1
*              - mldsa_polyveck *v0: pointer to output vector of polynomials with
*                              coefficients a0
*              - const mldsa_polyveck *v: pointer to input vector
**************************************************/
static void mldsa_polyveck_power2round(mldsa_polyveck *v1, mldsa_polyveck *v0, const mldsa_polyveck *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        mldsa_polyveck_decompose
*
* Description: For all coefficients a of polynomials in vector of length MLDSA_K,
*              compute high and low bits a0, a1 such a mod^+ MLDSA_Q = a1*ALPHA + a0
*              with -ALPHA/2 < a0 <= ALPHA/2 except a1 = (MLDSA_Q-1)/ALPHA where we
*              set a1 = 0 and -ALPHA/2 <= a0 = a mod MLDSA_Q - MLDSA_Q < 0.
*              Assumes coefficients to be standard representatives.
*
* Arguments:   - mldsa_polyveck *v1: pointer to output vector of polynomials with
*                              coefficients a1
*              - mldsa_polyveck *v0: pointer to output vector of polynomials with
*                              coefficients a0
*              - const mldsa_polyveck *v: pointer to input vector
**************************************************/
static void mldsa_polyveck_decompose(mldsa_polyveck *v1, mldsa_polyveck *v0, const mldsa_polyveck *v) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        mldsa_polyveck_make_hint
*
* Description: Compute hint vector.
*
* Arguments:   - mldsa_polyveck *h: pointer to output vector
*              - const mldsa_polyveck *v0: pointer to low part of input vector
*              - const mldsa_polyveck *v1: pointer to high part of input vector
*
* Returns number of 1 bits.
**************************************************/
static unsigned int mldsa_polyveck_make_hint(mldsa_polyveck *h,
                                const mldsa_polyveck *v0,
                                const mldsa_polyveck *v1)
{
  unsigned int i, s = 0;

  for(i = 0; i < MLDSA_K; ++i)
    s += mldsa_poly_make_hint(&h->vec[i], &v0->vec[i], &v1->vec[i]);

  return s;
}

/*************************************************
* Name:        mldsa_polyveck_use_hint
*
* Description: Use hint vector to correct the high bits of input vector.
*
* Arguments:   - mldsa_polyveck *w: pointer to output vector of polynomials with
*                             corrected high bits
*              - const mldsa_polyveck *u: pointer to input vector
*              - const mldsa_polyveck *h: pointer to input hint vector
**************************************************/
static void mldsa_polyveck_use_hint(mldsa_polyveck *w, const mldsa_polyveck *u, const mldsa_polyveck *h) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_poly_use_hint(&w->vec[i], &u->vec[i], &h->vec[i]);
}

static void mldsa_polyveck_pack_w1(uint8_t r[MLDSA_K*MLDSA_POLYW1_PACKEDBYTES], const mldsa_polyveck *w1) {
  unsigned int i;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_polyw1_pack(&r[i*MLDSA_POLYW1_PACKEDBYTES], &w1->vec[i]);
}

// ----- mldsa/packing.c -----
/*************************************************
* Name:        mldsa_pack_pk
*
* Description: Bit-pack public key pk = (rho, t1).
*
* Arguments:   - uint8_t pk[]: output byte array
*              - const uint8_t rho[]: byte array containing rho
*              - const mldsa_polyveck *t1: pointer to vector t1
**************************************************/
static void mldsa_pack_pk(uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
             const uint8_t rho[MLDSA_SEEDBYTES],
             const mldsa_polyveck *t1)
{
  unsigned int i;

  for(i = 0; i < MLDSA_SEEDBYTES; ++i)
    pk[i] = rho[i];
  pk += MLDSA_SEEDBYTES;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_polyt1_pack(pk + i*MLDSA_POLYT1_PACKEDBYTES, &t1->vec[i]);
}

/*************************************************
* Name:        mldsa_unpack_pk
*
* Description: Unpack public key pk = (rho, t1).
*
* Arguments:   - const uint8_t rho[]: output byte array for rho
*              - const mldsa_polyveck *t1: pointer to output vector t1
*              - uint8_t pk[]: byte array containing bit-packed pk
**************************************************/
static void mldsa_unpack_pk(uint8_t rho[MLDSA_SEEDBYTES],
               mldsa_polyveck *t1,
               const uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES])
{
  unsigned int i;

  for(i = 0; i < MLDSA_SEEDBYTES; ++i)
    rho[i] = pk[i];
  pk += MLDSA_SEEDBYTES;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_polyt1_unpack(&t1->vec[i], pk + i*MLDSA_POLYT1_PACKEDBYTES);
}

/*************************************************
* Name:        mldsa_pack_sk
*
* Description: Bit-pack secret key sk = (rho, tr, key, t0, s1, s2).
*
* Arguments:   - uint8_t sk[]: output byte array
*              - const uint8_t rho[]: byte array containing rho
*              - const uint8_t tr[]: byte array containing tr
*              - const uint8_t key[]: byte array containing key
*              - const mldsa_polyveck *t0: pointer to vector t0
*              - const mldsa_polyvecl *s1: pointer to vector s1
*              - const mldsa_polyveck *s2: pointer to vector s2
**************************************************/
static void mldsa_pack_sk(uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES],
             const uint8_t rho[MLDSA_SEEDBYTES],
             const uint8_t tr[MLDSA_TRBYTES],
             const uint8_t key[MLDSA_SEEDBYTES],
             const mldsa_polyveck *t0,
             const mldsa_polyvecl *s1,
             const mldsa_polyveck *s2)
{
  unsigned int i;

  for(i = 0; i < MLDSA_SEEDBYTES; ++i)
    sk[i] = rho[i];
  sk += MLDSA_SEEDBYTES;

  for(i = 0; i < MLDSA_SEEDBYTES; ++i)
    sk[i] = key[i];
  sk += MLDSA_SEEDBYTES;

  for(i = 0; i < MLDSA_TRBYTES; ++i)
    sk[i] = tr[i];
  sk += MLDSA_TRBYTES;

  for(i = 0; i < MLDSA_L; ++i)
    mldsa_polyeta_pack(sk + i*MLDSA_POLYETA_PACKEDBYTES, &s1->vec[i]);
  sk += MLDSA_L*MLDSA_POLYETA_PACKEDBYTES;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_polyeta_pack(sk + i*MLDSA_POLYETA_PACKEDBYTES, &s2->vec[i]);
  sk += MLDSA_K*MLDSA_POLYETA_PACKEDBYTES;

  for(i = 0; i < MLDSA_K; ++i)
    mldsa_polyt0_pack(sk + i*MLDSA_POLYT0_PACKEDBYTES, &t0->vec[i]);
}

/*************************************************
* Name:        mldsa_unpack_sk
*
* Description: Unpack secret key sk = (rho, tr, key, t0, s1, s2).
*
* Arguments:   - const uint8_t rho[]: output byte array for rho
*              - const uint8_t tr[]: output byte array for tr
*              - const uint8_t key[]: output byte array for key
*              - const mldsa_polyveck *t0: pointer to output vector t0
*              - const mldsa_polyvecl *s1: pointer to output vector s1
*              - const mldsa_polyveck *s2: pointer to output vector s2
*              - uint8_t sk[]: byte array containing bit-packed sk
**************************************************/
static void mldsa_unpack_sk(uint8_t rho[MLDSA_SEEDBYTES],
               uint8_t tr[MLDSA_TRBYTES],
               uint8_t key[MLDSA_SEEDBYTES],
               mldsa_polyveck *t0,
               mldsa_polyvecl *s1,
               mldsa_polyveck *s2,
               const uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES])
{
  unsigned int i;

  for(i = 0; i < MLDSA_SEEDBYTES; ++i)
    rho[i] = sk[i];
  sk += MLDSA_SEEDBYTES;

  for(i = 0; i < MLDSA_SEEDBYTES; ++i)
    key[i] = sk[i];
  sk += MLDSA_SEEDBYTES;

  for(i = 0; i < MLDSA_TRBYTES; ++i)
    tr[i] = sk[i];
  sk += MLDSA_TRBYTES;

  for(i=0; i < MLDSA_L; ++i)
    mldsa_polyeta_unpack(&s1->vec[i], sk + i*MLDSA_POLYETA_PACKEDBYTES);
  sk += MLDSA_L*MLDSA_POLYETA_PACKEDBYTES;

  for(i=0; i < MLDSA_K; ++i)
    mldsa_polyeta_unpack(&s2->vec[i], sk + i*MLDSA_POLYETA_PACKEDBYTES);
  sk += MLDSA_K*MLDSA_POLYETA_PACKEDBYTES;

  for(i=0; i < MLDSA_K; ++i)
    mldsa_polyt0_unpack(&t0->vec[i], sk + i*MLDSA_POLYT0_PACKEDBYTES);
}

/*************************************************
* Name:        mldsa_pack_sig
*
* Description: Bit-pack signature sig = (c, z, h).
*
* Arguments:   - uint8_t sig[]: output byte array
*              - const uint8_t *c: pointer to challenge hash length MLDSA_SEEDBYTES
*              - const mldsa_polyvecl *z: pointer to vector z
*              - const mldsa_polyveck *h: pointer to hint vector h
**************************************************/
static void mldsa_pack_sig(uint8_t sig[MLDSA_CRYPTO_BYTES],
              const uint8_t c[MLDSA_CTILDEBYTES],
              const mldsa_polyvecl *z,
              const mldsa_polyveck *h)
{
  unsigned int i, j, k;

  for(i=0; i < MLDSA_CTILDEBYTES; ++i)
    sig[i] = c[i];
  sig += MLDSA_CTILDEBYTES;

  for(i = 0; i < MLDSA_L; ++i)
    mldsa_polyz_pack(sig + i*MLDSA_POLYZ_PACKEDBYTES, &z->vec[i]);
  sig += MLDSA_L*MLDSA_POLYZ_PACKEDBYTES;

  /* Encode h */
  for(i = 0; i < MLDSA_OMEGA + MLDSA_K; ++i)
    sig[i] = 0;

  k = 0;
  for(i = 0; i < MLDSA_K; ++i) {
    for(j = 0; j < MLDSA_N; ++j)
      if(h->vec[i].coeffs[j] != 0)
        sig[k++] = j;

    sig[MLDSA_OMEGA + i] = k;
  }
}

/*************************************************
* Name:        mldsa_unpack_sig
*
* Description: Unpack signature sig = (c, z, h).
*
* Arguments:   - uint8_t *c: pointer to output challenge hash
*              - mldsa_polyvecl *z: pointer to output vector z
*              - mldsa_polyveck *h: pointer to output hint vector h
*              - const uint8_t sig[]: byte array containing
*                bit-packed signature
*
* Returns 1 in case of malformed signature; otherwise 0.
**************************************************/
static int mldsa_unpack_sig(uint8_t c[MLDSA_CTILDEBYTES],
               mldsa_polyvecl *z,
               mldsa_polyveck *h,
               const uint8_t sig[MLDSA_CRYPTO_BYTES])
{
  unsigned int i, j, k;

  for(i = 0; i < MLDSA_CTILDEBYTES; ++i)
    c[i] = sig[i];
  sig += MLDSA_CTILDEBYTES;

  for(i = 0; i < MLDSA_L; ++i)
    mldsa_polyz_unpack(&z->vec[i], sig + i*MLDSA_POLYZ_PACKEDBYTES);
  sig += MLDSA_L*MLDSA_POLYZ_PACKEDBYTES;

  /* Decode h */
  k = 0;
  for(i = 0; i < MLDSA_K; ++i) {
    for(j = 0; j < MLDSA_N; ++j)
      h->vec[i].coeffs[j] = 0;

    if(sig[MLDSA_OMEGA + i] < k || sig[MLDSA_OMEGA + i] > MLDSA_OMEGA)
      return 1;

    for(j = k; j < sig[MLDSA_OMEGA + i]; ++j) {
      /* Coefficients are ordered for strong unforgeability */
      if(j > k && sig[j] <= sig[j-1]) return 1;
      h->vec[i].coeffs[sig[j]] = 1;
    }

    k = sig[MLDSA_OMEGA + i];
  }

  /* Extra indices are zero for strong unforgeability */
  for(j = k; j < MLDSA_OMEGA; ++j)
    if(sig[j])
      return 1;

  return 0;
}

// ----- mldsa/symmetric-shake.c -----
static void mldsa_shake128_stream_init(keccak_state *state, const uint8_t seed[MLDSA_SEEDBYTES], uint16_t nonce)
{
  uint8_t t[2];
  t[0] = nonce;
  t[1] = nonce >> 8;

  shake128_init(state);
  shake128_absorb(state, seed, MLDSA_SEEDBYTES);
  shake128_absorb(state, t, 2);
  shake128_finalize(state);
}

static void mldsa_shake256_stream_init(keccak_state *state, const uint8_t seed[MLDSA_CRHBYTES], uint16_t nonce)
{
  uint8_t t[2];
  t[0] = nonce;
  t[1] = nonce >> 8;

  shake256_init(state);
  shake256_absorb(state, seed, MLDSA_CRHBYTES);
  shake256_absorb(state, t, 2);
  shake256_finalize(state);
}

// ----- mldsa/sign.c -----
/*************************************************
* Name:        mldsa_keypair
*
* Description: Generates public and private key.
*
* Arguments:   - uint8_t *pk: pointer to output public key (allocated
*                             array of MLDSA_CRYPTO_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key (allocated
*                             array of MLDSA_CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
static int mldsa_keypair_derand(uint8_t *pk, uint8_t *sk,
                               const uint8_t seed[MLDSA_SEEDBYTES]) {
  uint8_t seedbuf[2*MLDSA_SEEDBYTES + MLDSA_CRHBYTES];
  uint8_t tr[MLDSA_TRBYTES];
  const uint8_t *rho, *rhoprime, *key;
  mldsa_polyvecl mat[MLDSA_K];
  mldsa_polyvecl s1, s1hat;
  mldsa_polyveck s2, t1, t0;

  /* Get randomness for rho, rhoprime and key */
  memcpy(seedbuf, seed, MLDSA_SEEDBYTES);
  seedbuf[MLDSA_SEEDBYTES+0] = MLDSA_K;
  seedbuf[MLDSA_SEEDBYTES+1] = MLDSA_L;
  shake256(seedbuf, 2*MLDSA_SEEDBYTES + MLDSA_CRHBYTES, seedbuf, MLDSA_SEEDBYTES+2);
  rho = seedbuf;
  rhoprime = rho + MLDSA_SEEDBYTES;
  key = rhoprime + MLDSA_CRHBYTES;

  /* Expand matrix */
  mldsa_polyvec_matrix_expand(mat, rho);

  /* Sample short vectors s1 and s2 */
  mldsa_polyvecl_uniform_eta(&s1, rhoprime, 0);
  mldsa_polyveck_uniform_eta(&s2, rhoprime, MLDSA_L);

  /* Matrix-vector multiplication */
  s1hat = s1;
  mldsa_polyvecl_ntt(&s1hat);
  mldsa_polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
  mldsa_polyveck_reduce(&t1);
  mldsa_polyveck_invntt_tomont(&t1);

  /* Add error vector s2 */
  mldsa_polyveck_add(&t1, &t1, &s2);

  /* Extract t1 and write public key */
  mldsa_polyveck_caddq(&t1);
  mldsa_polyveck_power2round(&t1, &t0, &t1);
  mldsa_pack_pk(pk, rho, &t1);

  /* Compute H(rho, t1) and write secret key */
  shake256(tr, MLDSA_TRBYTES, pk, MLDSA_CRYPTO_PUBLICKEYBYTES);
  mldsa_pack_sk(sk, rho, tr, key, &t0, &s1, &s2);

  ncrypt_wipe(seedbuf, sizeof seedbuf);
  ncrypt_wipe(&s1,    sizeof s1);
  ncrypt_wipe(&s1hat, sizeof s1hat);
  ncrypt_wipe(&s2,    sizeof s2);
  ncrypt_wipe(&t0,    sizeof t0);
  return 0;
}

/*************************************************
* Name:        mldsa_signature_internal
*
* Description: Computes signature. Internal API.
*
* Arguments:   - uint8_t *sig:   pointer to output signature (of length MLDSA_CRYPTO_BYTES)
*              - size_t *siglen: pointer to output length of signature
*              - uint8_t *m:     pointer to message to be signed
*              - size_t mlen:    length of message
*              - uint8_t *pre:   pointer to prefix string
*              - size_t prelen:  length of prefix string
*              - uint8_t *rnd:   pointer to random seed
*              - uint8_t *sk:    pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/
static int mldsa_signature_internal(uint8_t *sig,
                                   size_t *siglen,
                                   const uint8_t *m,
                                   size_t mlen,
                                   const uint8_t *pre,
                                   size_t prelen,
                                   const uint8_t rnd[MLDSA_RNDBYTES],
                                   const uint8_t *sk)
{
  unsigned int n;
  uint8_t seedbuf[2*MLDSA_SEEDBYTES + MLDSA_TRBYTES + 2*MLDSA_CRHBYTES];
  uint8_t *rho, *tr, *key, *mu, *rhoprime;
  uint16_t nonce = 0;
  mldsa_polyvecl mat[MLDSA_K], s1, y, z;
  mldsa_polyveck t0, s2, w1, w0, h;
  mldsa_poly cp;
  keccak_state state;

  rho = seedbuf;
  tr = rho + MLDSA_SEEDBYTES;
  key = tr + MLDSA_TRBYTES;
  mu = key + MLDSA_SEEDBYTES;
  rhoprime = mu + MLDSA_CRHBYTES;
  mldsa_unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

  /* Compute mu = CRH(tr, pre, msg) */
  shake256_init(&state);
  shake256_absorb(&state, tr, MLDSA_TRBYTES);
  shake256_absorb(&state, pre, prelen);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, MLDSA_CRHBYTES, &state);

  /* Compute rhoprime = CRH(key, rnd, mu) */
  shake256_init(&state);
  shake256_absorb(&state, key, MLDSA_SEEDBYTES);
  shake256_absorb(&state, rnd, MLDSA_RNDBYTES);
  shake256_absorb(&state, mu, MLDSA_CRHBYTES);
  shake256_finalize(&state);
  shake256_squeeze(rhoprime, MLDSA_CRHBYTES, &state);

  /* Expand matrix and transform vectors */
  mldsa_polyvec_matrix_expand(mat, rho);
  mldsa_polyvecl_ntt(&s1);
  mldsa_polyveck_ntt(&s2);
  mldsa_polyveck_ntt(&t0);

rej:
  /* Sample intermediate vector y */
  mldsa_polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

  /* Matrix-vector multiplication */
  z = y;
  mldsa_polyvecl_ntt(&z);
  mldsa_polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
  mldsa_polyveck_reduce(&w1);
  mldsa_polyveck_invntt_tomont(&w1);

  /* Decompose w and call the random oracle */
  mldsa_polyveck_caddq(&w1);
  mldsa_polyveck_decompose(&w1, &w0, &w1);
  mldsa_polyveck_pack_w1(sig, &w1);

  shake256_init(&state);
  shake256_absorb(&state, mu, MLDSA_CRHBYTES);
  shake256_absorb(&state, sig, MLDSA_K*MLDSA_POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(sig, MLDSA_CTILDEBYTES, &state);
  mldsa_poly_challenge(&cp, sig);
  mldsa_poly_ntt(&cp);

  /* Compute z, reject if it reveals secret */
  mldsa_polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
  mldsa_polyvecl_invntt_tomont(&z);
  mldsa_polyvecl_add(&z, &z, &y);
  mldsa_polyvecl_reduce(&z);
  if(mldsa_polyvecl_chknorm(&z, MLDSA_GAMMA1 - MLDSA_BETA))
    goto rej;

  /* Check that subtracting cs2 does not change high bits of w and low bits
   * do not reveal secret information */
  mldsa_polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
  mldsa_polyveck_invntt_tomont(&h);
  mldsa_polyveck_sub(&w0, &w0, &h);
  mldsa_polyveck_reduce(&w0);
  if(mldsa_polyveck_chknorm(&w0, MLDSA_GAMMA2 - MLDSA_BETA))
    goto rej;

  /* Compute hints for w1 */
  mldsa_polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
  mldsa_polyveck_invntt_tomont(&h);
  mldsa_polyveck_reduce(&h);
  if(mldsa_polyveck_chknorm(&h, MLDSA_GAMMA2))
    goto rej;

  mldsa_polyveck_add(&w0, &w0, &h);
  n = mldsa_polyveck_make_hint(&h, &w0, &w1);
  if(n > MLDSA_OMEGA)
    goto rej;

  /* Write signature */
  mldsa_pack_sig(sig, sig, &z, &h);
  *siglen = MLDSA_CRYPTO_BYTES;

  ncrypt_wipe(seedbuf, sizeof seedbuf);
  ncrypt_wipe(&s1, sizeof s1);
  ncrypt_wipe(&s2, sizeof s2);
  ncrypt_wipe(&t0, sizeof t0);
  ncrypt_wipe(&y,  sizeof y);
  ncrypt_wipe(&w0, sizeof w0);
  ncrypt_wipe(&state, sizeof state);
  return 0;
}

/*************************************************
* Name:        mldsa_signature
*
* Description: Computes signature.
*
* Arguments:   - uint8_t *sig:   pointer to output signature (of length MLDSA_CRYPTO_BYTES)
*              - size_t *siglen: pointer to output length of signature
*              - uint8_t *m:     pointer to message to be signed
*              - size_t mlen:    length of message
*              - uint8_t *ctx:   pointer to contex string
*              - size_t ctxlen:  length of contex string
*              - uint8_t *sk:    pointer to bit-packed secret key
*
* Returns 0 (success) or -1 (context string too long)
**************************************************/
static int mldsa_signature(uint8_t *sig,
                          size_t *siglen,
                          const uint8_t *m,
                          size_t mlen,
                          const uint8_t *ctx,
                          size_t ctxlen,
                          const uint8_t *sk)
{
  size_t i;
  uint8_t pre[257];
  uint8_t rnd[MLDSA_RNDBYTES];

  if(ctxlen > 255)
    return -1;

  /* Prepare pre = (0, ctxlen, ctx) */
  pre[0] = 0;
  pre[1] = ctxlen;
  for(i = 0; i < ctxlen; i++)
    pre[2 + i] = ctx[i];

  for(i=0;i<MLDSA_RNDBYTES;i++)
    rnd[i] = 0;

  mldsa_signature_internal(sig,siglen,m,mlen,pre,2+ctxlen,rnd,sk);
  return 0;
}


/*************************************************
* Name:        mldsa_verify_internal
*
* Description: Verifies signature. Internal API.
*
* Arguments:   - uint8_t *m: pointer to input signature
*              - size_t siglen: length of signature
*              - const uint8_t *m: pointer to message
*              - size_t mlen: length of message
*              - const uint8_t *pre: pointer to prefix string
*              - size_t prelen: length of prefix string
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signature could be verified correctly and -1 otherwise
**************************************************/
static int mldsa_verify_internal(const uint8_t *sig,
                                size_t siglen,
                                const uint8_t *m,
                                size_t mlen,
                                const uint8_t *pre,
                                size_t prelen,
                                const uint8_t *pk)
{
  unsigned int i;
  uint8_t buf[MLDSA_K*MLDSA_POLYW1_PACKEDBYTES];
  uint8_t rho[MLDSA_SEEDBYTES];
  uint8_t mu[MLDSA_CRHBYTES];
  uint8_t c[MLDSA_CTILDEBYTES];
  uint8_t c2[MLDSA_CTILDEBYTES];
  mldsa_poly cp;
  mldsa_polyvecl mat[MLDSA_K], z;
  mldsa_polyveck t1, w1, h;
  keccak_state state;

  if(siglen != MLDSA_CRYPTO_BYTES)
    return -1;

  mldsa_unpack_pk(rho, &t1, pk);
  if(mldsa_unpack_sig(c, &z, &h, sig))
    return -1;
  if(mldsa_polyvecl_chknorm(&z, MLDSA_GAMMA1 - MLDSA_BETA))
    return -1;

  /* Compute CRH(H(rho, t1), pre, msg) */
  shake256(mu, MLDSA_TRBYTES, pk, MLDSA_CRYPTO_PUBLICKEYBYTES);
  shake256_init(&state);
  shake256_absorb(&state, mu, MLDSA_TRBYTES);
  shake256_absorb(&state, pre, prelen);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, MLDSA_CRHBYTES, &state);

  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  mldsa_poly_challenge(&cp, c);
  mldsa_polyvec_matrix_expand(mat, rho);

  mldsa_polyvecl_ntt(&z);
  mldsa_polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

  mldsa_poly_ntt(&cp);
  mldsa_polyveck_shiftl(&t1);
  mldsa_polyveck_ntt(&t1);
  mldsa_polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

  mldsa_polyveck_sub(&w1, &w1, &t1);
  mldsa_polyveck_reduce(&w1);
  mldsa_polyveck_invntt_tomont(&w1);

  /* Reconstruct w1 */
  mldsa_polyveck_caddq(&w1);
  mldsa_polyveck_use_hint(&w1, &w1, &h);
  mldsa_polyveck_pack_w1(buf, &w1);

  /* Call random oracle and verify challenge */
  shake256_init(&state);
  shake256_absorb(&state, mu, MLDSA_CRHBYTES);
  shake256_absorb(&state, buf, MLDSA_K*MLDSA_POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(c2, MLDSA_CTILDEBYTES, &state);
  for(i = 0; i < MLDSA_CTILDEBYTES; ++i)
    if(c[i] != c2[i])
      return -1;

  return 0;
}

/*************************************************
* Name:        mldsa_verify
*
* Description: Verifies signature.
*
* Arguments:   - uint8_t *m: pointer to input signature
*              - size_t siglen: length of signature
*              - const uint8_t *m: pointer to message
*              - size_t mlen: length of message
*              - const uint8_t *ctx: pointer to context string
*              - size_t ctxlen: length of context string
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signature could be verified correctly and -1 otherwise
**************************************************/
static int mldsa_verify(const uint8_t *sig,
                       size_t siglen,
                       const uint8_t *m,
                       size_t mlen,
                       const uint8_t *ctx,
                       size_t ctxlen,
                       const uint8_t *pk)
{
  size_t i;
  uint8_t pre[257];

  if(ctxlen > 255)
    return -1;

  pre[0] = 0;
  pre[1] = ctxlen;
  for(i = 0; i < ctxlen; i++)
    pre[2 + i] = ctx[i];

  return mldsa_verify_internal(sig,siglen,m,mlen,pre,2+ctxlen,pk);
}

////////////////////////////
/// Public API (ML-KEM)  ///
////////////////////////////

void ncrypt_mlkem768_key_pair(uint8_t secret_key[2400],
                              uint8_t public_key[1184],
                              uint8_t seed      [64])
{
	(void)mlkem_keypair_derand(public_key, secret_key, seed);
	ncrypt_wipe(seed, 64);
}

int ncrypt_mlkem768_encapsulate(uint8_t       ciphertext   [1088],
                                uint8_t       shared_secret[32],
                                const uint8_t public_key   [1184],
                                uint8_t       seed         [32])
{
	// FIPS 203 asks us to reject encapsulation keys whose
	// coefficients are not reduced mod q.  The reference unpacking
	// keeps raw 12 bit values, so check them against q directly.
	mlkem_polyvec t;
	size_t i, j;
	mlkem_polyvec_frombytes(&t, public_key);
	for (i = 0; i < KYBER_K; i++) {
		for (j = 0; j < KYBER_N; j++) {
			if (t.vec[i].coeffs[j] >= KYBER_Q) {
				ncrypt_wipe(seed, 32);
				return -1;
			}
		}
	}

	(void)mlkem_enc_derand(ciphertext, shared_secret, public_key, seed);
	ncrypt_wipe(seed, 32);
	return 0;
}

int ncrypt_mlkem768_decapsulate(uint8_t       shared_secret[32],
                                const uint8_t ciphertext   [1088],
                                const uint8_t secret_key   [2400])
{
	// FIPS 203 hash check: the key must still contain the digest
	// of its own public half.  Catches corrupted imports; forged
	// ciphertexts are absorbed by implicit rejection instead.
	uint8_t h[32];
	sha3_256(h, secret_key + KYBER_INDCPA_SECRETKEYBYTES,
	         KYBER_PUBLICKEYBYTES);
	if (ncrypt_verify32(h, secret_key + KYBER_SECRETKEYBYTES
	                       - 2*KYBER_SYMBYTES) != 0) {
		return -1;
	}
	(void)mlkem_dec(shared_secret, ciphertext, secret_key);
	return 0;
}


////////////////////////////
/// Public API (ML-DSA)  ///
////////////////////////////

void ncrypt_mldsa44_key_pair(uint8_t secret_key[2560],
                             uint8_t public_key[1312],
                             uint8_t seed      [32])
{
	(void)mldsa_keypair_derand(public_key, secret_key, seed);
	ncrypt_wipe(seed, 32);
}

void ncrypt_mldsa44_sign(uint8_t        signature [2420],
                         const uint8_t  secret_key[2560],
                         const uint8_t *message, size_t message_size)
{
	// Pure ML-DSA-44, deterministic, empty context.  The empty
	// context cannot overflow, so mldsa_signature cannot fail.
	size_t sig_size;
	(void)mldsa_signature(signature, &sig_size,
	                      message, message_size, 0, 0, secret_key);
}

int ncrypt_mldsa44_check(const uint8_t  signature [2420],
                         const uint8_t  public_key[1312],
                         const uint8_t *message, size_t message_size)
{
	return mldsa_verify(signature, MLDSA_CRYPTO_BYTES,
	                    message, message_size, 0, 0, public_key);
}


////////////////////////////
/// High level wrappers  ///
////////////////////////////

void ncrypt_pqc_key_pair(uint8_t secret_key[2400],
                         uint8_t public_key[1184],
                         uint8_t seed      [64])
{
	ncrypt_mlkem768_key_pair(secret_key, public_key, seed);
}

void ncrypt_pqc_sign_key_pair(uint8_t secret_key[2560],
                              uint8_t public_key[1312],
                              uint8_t seed      [32])
{
	ncrypt_mldsa44_key_pair(secret_key, public_key, seed);
}

// The message key only ever protects a single message (the KEM
// secret is fresh every time), so a fixed nonce is safe.  Hashing
// the KEM ciphertext into the key also pins the AEAD text to this
// exact encapsulation.
static void pqc_message_key(uint8_t key[32], const uint8_t shared[32],
                            const uint8_t kem_ct[1088])
{
	ncrypt_blake2b_keyed(key, 32, shared, 32, kem_ct, 1088);
}

int ncrypt_pqc_encrypt(uint8_t       *cipher_text,
                       uint8_t        mac       [16],
                       uint8_t        kem_ct    [1088],
                       const uint8_t  their_public_key[1184],
                       uint8_t        seed      [32],
                       const uint8_t *ad,         size_t ad_size,
                       const uint8_t *plain_text, size_t text_size)
{
	uint8_t shared[32];
	uint8_t key   [32];
	const uint8_t nonce[24] = {0};

	if (ncrypt_mlkem768_encapsulate(kem_ct, shared,
	                                their_public_key, seed) != 0) {
		return -1;
	}
	pqc_message_key(key, shared, kem_ct);
	ncrypt_aead_lock(cipher_text, mac, key, nonce,
	                 ad, ad_size, plain_text, text_size);
	ncrypt_wipe(shared, sizeof shared);
	ncrypt_wipe(key,    sizeof key);
	return 0;
}

int ncrypt_pqc_decrypt(uint8_t       *plain_text,
                       const uint8_t  kem_ct    [1088],
                       const uint8_t  mac       [16],
                       const uint8_t  secret_key[2400],
                       const uint8_t *ad,          size_t ad_size,
                       const uint8_t *cipher_text, size_t text_size)
{
	uint8_t shared[32];
	uint8_t key   [32];
	const uint8_t nonce[24] = {0};
	int mismatch;

	if (ncrypt_mlkem768_decapsulate(shared, kem_ct, secret_key) != 0) {
		return -1;
	}
	pqc_message_key(key, shared, kem_ct);
	mismatch = ncrypt_aead_unlock(plain_text, mac, key, nonce,
	                              ad, ad_size, cipher_text, text_size);
	ncrypt_wipe(shared, sizeof shared);
	ncrypt_wipe(key,    sizeof key);
	return mismatch;
}

void ncrypt_pqc_sign(uint8_t        signature [2420],
                     const uint8_t  secret_key[2560],
                     const uint8_t *message, size_t message_size)
{
	ncrypt_mldsa44_sign(signature, secret_key, message, message_size);
}

int ncrypt_pqc_check(const uint8_t  signature [2420],
                     const uint8_t  public_key[1312],
                     const uint8_t *message, size_t message_size)
{
	return ncrypt_mldsa44_check(signature, public_key,
	                            message, message_size);
}
