test_v4: test_v4.o
	gcc -o test-v4 test_v4.c -lpcap
clear:
	rm test_v4