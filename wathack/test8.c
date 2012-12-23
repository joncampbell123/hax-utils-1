#include <stdio.h>

extern char this_is_arbitrary_data[];
/* NTS: ^ extern char* implies that the asm file declared a 16-bit or 32-bit
 *        value holding a memory location to where the string can be found,
 *        under that name. test2a.asm defines only the string and a label
 *        where it can be found, thus we must tell the compiler it is char[] */

int main() {
	printf("Hello world\n");
	printf("%s\n",this_is_arbitrary_data);
	return 0;
}
