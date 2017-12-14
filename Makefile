sniffer:
	gcc -o sniffer sniffer.c -lpcap `pkg-config --cflags --libs glib-2.0`
clear:
	rm -rf sniffer
