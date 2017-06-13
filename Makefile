CFLAGS=-g -Wall -Werror `ldns-config --cflags`
LDFLAGS=`ldns-config --libs` -Lcrypto

LDNS_MERGEZONE_OBJECTS=\
main.o \
merge.o \
verify.o \
verbose.o \
dnssec_ht.o

all: ldns-mergezone

ldns-mergezone: ${LDNS_MERGEZONE_OBJECTS}
	${CC} -o ldns-mergezone ${LDNS_MERGEZONE_OBJECTS} ${LDFLAGS} -pthread -lm

clean:
	rm -f ldns-mergezone *.o

