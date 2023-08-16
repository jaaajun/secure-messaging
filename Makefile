FLAG = -Wall -I./include/

.PHONY : all
all : server client

server : server.o database.o log.o queue.o secure.o 
	clang -o server $(FLAG) server.o database.o log.o queue.o secure.o \
							-lmysqlclient -lcrypto -pthread
client : client.o secure.o
	clang -o client $(FLAG) client.o secure.o -lcrypto -pthread

server.o : ./src/server.c ./include/database.h ./include/log.h \
		  ./include/queue.h ./include/secure.h ./include/protocol.h
	clang -c $(FLAG) ./src/server.c
client.o : ./src/client.c ./include/secure.h ./include/protocol.h
	clang -c $(FLAG) ./src/client.c

database.o : ./src/database.c ./include/database.h ./include/protocol.h
	clang -c $(FLAG) ./src/database.c
log.o : ./src/log.c ./include/log.h ./include/protocol.h
	clang -c $(FLAG) ./src/log.c
queue.o : ./src/queue.c ./include/queue.h ./include/protocol.h
	clang -c $(FLAG) ./src/queue.c
secure.o : ./src/secure.c ./include/secure.h ./include/protocol.h
	clang -c $(FLAG) ./src/secure.c

clean :
	rm server.o client.o database.o log.o queue.o secure.o
