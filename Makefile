ifeq ($(shell uname),Darwin)
	    LDFLAGS := -Wl,-dead_strip -lsodium
    else
	    LDFLAGS := -Wl,--gc-sections -lpthread -ldl -lsodium

    endif

praosvrf:
	$(CC) $(LDFLAGS) praos_vrf.c -o praos_bench || (echo "Make sure you have the right version of libsodium installed. See README.md"; exit 1)

batch:
	$(CC) $(LDFLAGS) batch_verify.c -o batch_bench || (echo "Make sure you have the right version of libsodium installed. See README.md"; exit 1)

clean:
		rm -rf praos_bench batch_bench results_batch.csv results_praos.csv
