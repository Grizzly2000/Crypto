#include "dh.h"

void a(u *x, u *y, int o, int S)
{
	int d = 0;
	int v;
	for (v = S;v--;)
	{
		d += x[v] + y[v] * o;
		x[v] = d;d = d >> 8;
	}
}

void s(u *x, u *m, int S)
{
	int v;
	for (v = 0;(v<S - 1) && (x[v] == m[v]); )
		v++;
	if (x[v] >= m[v])a(x, m, -1, S);
}

void r(u *x, int S)
{
	int v;
	int d = 0;
	for (v = 0;v< S;)
	{
		d |= x[v];
		x[v++] = d / 2;
		d = (d & 1) << 8;
	}
}

void M(u *x, u *y, u *m, int S)
{
	u X[DH_SIZE], Y[DH_SIZE];
	int z = 0;

	memcpy(X, x, S);
	memcpy(Y, y, S);
	memset(x, 0, S);
	for (z = S * 8;z--;)
	{
		if (X[S - 1] & 1)
		{
			a(x, Y, 1, S);
			s(x, m, S);
		}

		r(X, S);
		a(Y, Y, 1, S);
		s(Y, m, S);
	}
}

void tohex(char *x, u *y, int S)
{
	int n = 0;
	int z = 0;
	memset(y, 0, S);
	for (n = 0;x[n]>0;n++)
	{
		for (z = 4;z--;)
			a(y, y, 1, S);
		x[n] |= 32;y[S - 1] |= x[n] - 48 - (x[n]>96) * 39;
	}
}

void tostr(u *x, int S)
{
	int n = 0;
	for (n = 0;!x[n];)n++;
	for (;n< S;n++)
		printf("%c%c", 48 + x[n] / 16 + (x[n]>159) * 7, 48 + (x[n] & 15) + 7 * ((x[n] & 15)>9));
	printf("\n");
}

void exp_mod(u *g, u *e, u *m, u *b, int S)
{
	int n = 0;
	memset(b, 0, S);
	b[S - 1] = 1;
	for (n = S * 8;n--;)
	{
		if (e[S - 1] & 1)M(b, g, m, S);
		M(g, g, m, S);
		r(e, S);
	}

	tostr(b, S);
}