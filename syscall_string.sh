#!/bin/sh

grep __NR_ /usr/include/x86_64-linux-gnu/asm/unistd_64.h |
	awk 'BEGIN { print "static char* syscall_list[] = {" }
	     { print "/* " $3 " */ \"" $2 "\"," }
	     END { print "};" }'

cat <<EOF

const char *syscall_string(int num)
{
	return (syscall_list[num]);
}
EOF
