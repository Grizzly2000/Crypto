#include <stdio.h>
#include <stdlib.h>
#include <memory.h>


/*Amazing portable implementation of DH
http://www.cypherspace.org/rsa/dh-in-C.html
*/

#define DH_SIZE 2048
typedef unsigned char u;

void a(u *x, u *y, int o, int S);
void s(u *x, u *m, int S);
void r(u *x, int S);
void M(u *x, u *y, u *m, int S);
void tohex(char *x, u *y, int S);
void tostr(u *x, int S);
void exp_mod(u *g, u *e, u *m, u *b, int S);