test_v2: test_v2.o
	gcc -o test-v2 test_v2.c -lpcap
clear:
	rm test_v2