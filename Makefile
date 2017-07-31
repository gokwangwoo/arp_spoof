test_v2: test_v2.o
	gcc -o test-v3 test_v3.c -lpcap
clear:
	rm test_v3