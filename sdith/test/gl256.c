#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

/*************************************************/
/***********      FIELD OPERATIONS     ***********/
/*************************************************/

#define MODULUS 0x1B

uint8_t gf256_add(uint8_t a, uint8_t b)
{
  return a ^ b;
}

uint8_t gf256_mul(uint8_t a, uint8_t b)
{
  uint8_t r;
  r = (-(b >> 7) & a);
  r = (-(b >> 6 & 1) & a) ^ (-(r >> 7) & MODULUS) ^ (r + r);
  r = (-(b >> 5 & 1) & a) ^ (-(r >> 7) & MODULUS) ^ (r + r);
  r = (-(b >> 4 & 1) & a) ^ (-(r >> 7) & MODULUS) ^ (r + r);
  r = (-(b >> 3 & 1) & a) ^ (-(r >> 7) & MODULUS) ^ (r + r);
  r = (-(b >> 2 & 1) & a) ^ (-(r >> 7) & MODULUS) ^ (r + r);
  r = (-(b >> 1 & 1) & a) ^ (-(r >> 7) & MODULUS) ^ (r + r);
  return (-(b & 1) & a) ^ (-(r >> 7) & MODULUS) ^ (r + r);
}

int main(int argc, char const *argv[])
{
  uint8_t a = 0xff;
  uint8_t b = 0xff;
  uint8_t c = gf256_add(a, b);
  // print
  printf("a = %d\n", a);
  printf("b = %d\n", b);
  printf("c = %d\n", c);
  return 0;
}
