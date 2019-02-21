CCFLAGS  =  -MD -Wall -D_DEFAULT_SOURCE -D_GNU_SOURCE
CFLAGS   = $(CCFLAGS) -std=c99
SOURCES  = $(wildcard *.c)
OBJECTS  = $(SOURCES:.c=.o)
NAME     = pknockd

#ifdef CROSS_COMPILE
CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar
STRIP = $(CROSS_COMPILE)strip
OBJCOPY = $(CROSS_COMPILE)objcopy
#endif
ifdef LTO
CCFLAGS+=-flto -O3
LDFLAGS+=-flto -O3
endif

all: $(NAME)

debug:
	+make clean
	+make CFLAGS="$(CCFLAGS) -ggdb3" all

$(NAME).full: $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(NAME): $(NAME).full
	$(OBJCOPY) --only-keep-debug $^ $(NAME).debug
	$(STRIP) -o $@ $^
	$(OBJCOPY) --add-gnu-debuglink=$^ $(NAME)

clean:
	rm -f *.o *.d $(NAME) $(NAME).full $(NAME).debug

include $(wildcard *.d)
