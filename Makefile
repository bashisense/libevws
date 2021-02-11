
#
# Copyright (c) 2021, Bashi Tech. All rights reserved.
#

CC	= $(CROSS)gcc 
CXX	= $(CROSS)g++ -std=c++11
LD	= $(CROSS)ld
AR	= $(CROSS)ar
STRIP = $(CROSS)strip
RM	= @echo " RM	"; rm -f

CFLAGS += -g -Wall -DMQTT_GOJIN=1 -I/usr/local/include/luajit-2.1 -I./include
LIBS = -lluajit-5.1 -lssl -lcrypto -levent -levent_openssl -levent_pthreads -pthread -lssl -ldl

LDFLAGS = -rdynamic $(LIBS)

vpath %.c .


objs =					\
	evws.o 				\
	main.o 

#	evws.o			\
	main.o 	\
	client.o 

TARGET = ws


%.o : %.c
	$(CC) $(CFLAGS) -c -o objs/$@  $<

all : $(objs)
	$(CXX) -o $(TARGET) $(addprefix objs/, $(objs)) $(LDFLAGS)
	-$(STRIP) -s $(TARGET)

clean: 
	rm -f $(addprefix objs/, $(objs))  $(TARGET)
