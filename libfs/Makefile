# Target library

#lib := libfs.a

#all: $(lib)

## TODO: Phase 1
# Target library
lib := libfs.a

all: $(lib)
CC = gcc
FLAGS = -Wall -Wextra -Werror
OBJS = disk.o fs.o

ifneq ($(V),1)
Q = @
endif

deps := $(patsubst %.o, %d, $(OBJS))
-include $(deps)

libfs.a: $(OBJS)
	@echo "CC  @"
	$(Q) ar rcs $@ $^
fs.o: fs.c fs.h disk.h	
	@echo "CC  $@"
	$(Q) $(CC) $(FLAGS) -c -o $@ $<

disk.o: disk.c disk.h
	@echo "CC  $@"
	$(Q) $(CC) $(FLAGS) -c -o $@ $<

clean:
	@echo "clean"
	$(Q)rm -f $(lib) $(OBJS)
