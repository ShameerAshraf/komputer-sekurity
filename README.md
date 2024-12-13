#Syed Shameer Ashraf, shameer.ashraf@alumni.utoronto.ca

target1:
	char buf[96] is in lab_main, and so has the return address of lab_main closest to it. Writing past buf's end, we overwrite int t as well but it does not matter in this case. Then we overwrite lab_main's return address to point to buf's start where we placed the shellcode after some NOPs. 
	Exact address of return address on stack had to be determined so the upper bytes of return address were not written to. This was used to place the start address of buf at the right place in the input string for target program.

target2:
	Overflowing char buf[256], we can overwrite values for i and len the for loop continues to run for a little while longer. Then, we can overwrite foo's return address. Maximum length for input is set to 272 bytes which is enough to reach both int i and int len.
	'env' variables had to be used after the 'argv' variables because the replacement value for len had null bytes and the rest of the input string would not be copied into argv when starting the target program.

target3:
	Overflowing char buf[64] is possible because the length of buf is set to no less than 88. It allows us to simply overwrite the return address of foo. 
	First 4 bytes of buf were already written to, so foo's return address has to be set to 'start of buf + 4 bytes' in order to get the shellcode running. 'env' variables were not necessary to use.

target4:
	char buf[156] is on the stack at 0x2021fdb0 where overflowing it will write to variables above it (i and len) and also foo's return address at 0x2021fe68.
	Checking arg's length does not protect the target because len = 169 bytes is enough for the loop to go past the end of the buffer and write to the variable len to allow the for loop to execute for a little while longer.
	argv[1] contains NOPs at the start, shellcode in the middle and replacement value for len, i and return address at the end.

More explanations in code comments...
