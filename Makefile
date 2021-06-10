ifeq ($(shell uname),Darwin)
	    LDFLAGS := -Wl,-dead_strip -lsodium
    else
	    LDFLAGS := -Wl,--gc-sections -lpthread -ldl -lsodium

    endif

all: 
	$(CC) $(LDFLAGS)  main.c -o vrf_tests

clean:
		rm -rf vrf_tests
