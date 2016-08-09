CFLAGS += -O2 -g -W -Wall
LDFLAGS += -pthread

TEST_PROGS := isolation

all: $(TEST_PROGS)

include ../lib.mk

clean:
	$(RM) $(TEST_PROGS)
