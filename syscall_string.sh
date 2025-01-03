#!/bin/sh

grep __NR_ /usr/include/x86_64-linux-gnu/asm/unistd_64.h |
	sed 's/__NR_//' |
	awk 'BEGIN { print "static char* syscall_list[] = {" }
	     { print "[" $3 "] = \"" $2 "\"," }
	     END { print "};" }'

cat <<EOF

const char *syscall_string(int num)
{
	if (num < 0 || num >= sizeof(syscall_list) / sizeof(syscall_list[0]) ||
			syscall_list[num] == 0)
		return ("unknown");
	return (syscall_list[num]);
}
EOF
