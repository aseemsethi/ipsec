CC=gcc
CFLAGS=-g -I. -DTEST
OBJ = crypto.o  os.o dh_groups.o sha1.o md5.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)
go: $(OBJ)
	$(CC) -c $^ $(CFLAGS)
clean:
	rm -f *.o go
