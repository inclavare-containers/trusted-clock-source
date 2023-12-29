gcc client.c common.c -libverbs -lpthread -o client.o
gcc server.c common.c -libverbs -lpthread -o server.o