CC=gcc
CFLAGS=-c
LDFLAGS=
SOURCES= rsa.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=rsa.exe

all: clean $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) -o $@ $(OBJECTS) $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf *.o *.exe

test:
	./$(EXECUTABLE)
