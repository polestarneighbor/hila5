# Makefile
# 2018-02-18  Hannah Davis <davi2495@umn.edu>
# (Reference Implementation)

BIN	= genkat_ref
OBJS	= kem.o hila5_sha3_ref.o pake.o \
	../KAT/src/rng.o ../KAT/src/PQCgenKAT_pake.o

CC	?= gcc
CFLAGS	+= -std=c99 -Wall -Ofast -I.
LDLIBS	+= -lcrypto
LDFLAGS	+=

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $(BIN) $(OBJS) $(LDLIBS)

test:	$(BIN)
	@echo ""
	./$(BIN) password password
#	@echo "== BEGIN KAT DIFFERENCE =="
#	@diff PQCkemKAT_1824.rsp ../KAT/PQCkemKAT_1824.rsp
#	@echo "== END KAT DIFFERENCE =="

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJS) $(BIN) PQCpakeKAT_3616.* ../KAT/PQCpakeKAT_3616.*
	rm -rf PQCkemKAT_3616.* ../KAT/PQCkemKAT_3616.*
