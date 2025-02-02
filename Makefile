CC=gcc
darwin:
	$(CC) -o clipboard clipboard.c -ggdb -I/opt/homebrew/Cellar/openssl@3/3.4.0/include -L/opt/homebrew/Cellar/openssl@3/3.4.0/lib -lssl -lcrypto -framework ApplicationServices

linux:
	$(CC) -o secure_clipboard secure_clipboard.c -ggdb -lssl -lcrypto -lX11
