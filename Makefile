FLAGS:=$(shell pkg-config --cflags --libs glib-2.0)
FLAGS+=-I$(shell pwd) -O0 -lpcap
HFILES:=pcapstreamer.h
SFILES:=pcapstreamer.c pcs_functions.c
OUTPUT:=pcapstreamer
CC:=gcc

all: $(HFILES) $(SFILES)
	$(CC) $(FLAGS) -o $(OUTPUT) $(HFILES) $(SFILES)

clean:
	rm $(OUTPUT)

.PHONY: clean