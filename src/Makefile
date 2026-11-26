PROG:=	exfat_faultgen
SRCS:=	faults_bitmap.c \
	faults_boot.c \
	faults_dentry.c \
	faults_fat.c \
	io.c \
	main.c \
	subr.c \
	utils_all.c \
	utils_bitmap.c \
	utils_boot.c \
	utils_dentry.c \
	utils_fat.c \
	utils_verify.c
OBJS:=	$(SRCS:.c=.o)

CFLAGS+=	-Wall -Wextra -Werror -Wshadow -Wstrict-prototypes
CFLAGS+=	-Wmissing-prototypes -Wpointer-arith -std=gnu17

all: $(PROG)

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

clean:
	rm -f $(OBJS) $(PROG)
