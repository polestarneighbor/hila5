# Makefile
# 2017-09-23  Markku-Juhani O. Saarinen <mjos@iki.fi>
# (Optimized Implementation)

BIN	= genkat_opt
OBJS	= kem.o hila5_sha3_opt.o ms_ntt.o ms_ntt_const.o pake.o \
	../KAT/src/rng.o
PAKE = ../KAT/src/pake_timer.o
PPK = ../KAT/src/ppk_timer.o
CC	?= gcc
CFLAGS	+= -std=c99 -Wall -Ofast -I.
LDLIBS	+= -lcrypto
LDFLAGS	+= -L/usr/local/opt/openssl/lib
$(BIN): $(OBJS) $(PAKE) $(PPK)
	$(CC) $(LDFLAGS) -o $(BIN)_pake $(OBJS) $(PAKE) $(LDLIBS)
	$(CC) $(LDFLAGS) -o $(BIN)_ppk $(OBJS) $(PPK) $(LDLIBS)

test:	$(BIN)
	./$(BIN)_pake password password | less 
	./$(BIN)_ppk password password

.c.o:
	$(CC) $(CFLAGS) $(INCS) -c $< -o $@

clean:
	rm -rf $(OBJS) $(BIN) PQCkem* ../KAT/PQCkem* PQCpake*
