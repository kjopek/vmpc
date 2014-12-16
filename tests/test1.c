#include <stdio.h>
#include <stdlib.h>

#include "vmpc_encrypt.h"

void
test_case_1(void)
{
	uint8_t k[16] = {0x01, 0x02, 0x03, 0x04,
			0x05, 0x06, 0x07, 0x08,
			0x09, 0x0A, 0x0B, 0x0C,
			0x0D, 0x0D, 0x0E, 0x0F};
	
	int out[256];
	int i = 0;

    struct vmpc_ctx * ctx = vmpc_ksa(16, k, 0, NULL);

	for (i=0; i<256; ++i)
		out[i] = 0;

    for (i=0; i<1000000; ++i) {
        out[vmpc_yield(ctx)]++;
	}

	for (i=0;i<256; ++i) {
		printf ("%03d ", out[i]);
		if (i % 8 == 7) 
			printf("\n");
	}
		
    vmpc_clean(ctx);
}

int 
main()
{
	test_case_1();
	return 0;
}
