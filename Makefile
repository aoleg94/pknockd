CCFLAGS  =  -MD -Wall -D_DEFAULT_SOURCE -D_GNU_SOURCE
CFLAGS   = $(CCFLAGS) -std=c99
SOURCES  = $(wildcard *.c)
OBJECTS  = $(SOURCES:.c=.o)
NAME     = pknockd

ifdef CROSS_COMPILE
CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar
endif

all: $(NAME)

debug:
	+make clean
	+make CFLAGS="$(CCFLAGS) -ggdb3" all

$(NAME): $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o $(NAME)

include $(wildcard *.d)
