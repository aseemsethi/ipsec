CC=gcc
CFLAGS=-g -I.
DEPS = sim.h
OBJ = sim.o net.o ikeStart.o crypto/os.o crypto/crypto.o crypto/dh_groups.o crypto/sha1.o crypto/md5.o


%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)
go: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) -lpthread -lgcrypt
clean:
	rm -f *.o go
