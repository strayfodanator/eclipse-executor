CC = gcc
CFLAGS = -Wall -Wextra -O2
GTK_FLAGS = `pkg-config --cflags --libs gtk4`
LDFLAGS = -ldl -lpthread

all: eclipse-ui injector eclipse.so

eclipse-ui: EclipseUI.c
	$(CC) $(CFLAGS) EclipseUI.c -o eclipse-ui $(GTK_FLAGS) $(LDFLAGS)

injector: Injector.c
	$(CC) $(CFLAGS) Injector.c -o injector $(LDFLAGS)

eclipse.so: injected_lib.c
	$(CC) $(CFLAGS) -shared -fPIC injected_lib.c -o eclipse.so $(LDFLAGS)

clean:
	rm -f eclipse-ui injector eclipse.so

.PHONY: all clean
