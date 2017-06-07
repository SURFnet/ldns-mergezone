CFLAGS=-g -Wall -Werror `ldns-config --cflags`
LDFLAGS=`ldns-config --libs` 

LDNS_MERGEZONE_OBJECTS=\
main.o \
merge.o

all: ldns-mergezone

ldns-mergezone: ${LDNS_MERGEZONE_OBJECTS}
	${CC} -o ldns-mergezone ${LDNS_MERGEZONE_OBJECTS} ${LDFLAGS} -pthread -lm

clean:
	rm -f ldns-mergezone *.o

