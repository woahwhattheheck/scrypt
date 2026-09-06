#!/bin/sh

### Constants
input_file="${s_basename}-input.txt"
named_stderr="${s_basename}-named.stderr"
stdout_stderr="${s_basename}-stdout.stderr"

scenario_cmd() {
	# /dev/full is available on Linux but not on every test platform.
	if [ ! -c /dev/full ]; then
		setup_check "scrypt enc named output close failure"
		echo "-1" > "${c_exitfile}"
		setup_check "scrypt enc named output close error"
		echo "-1" > "${c_exitfile}"
		setup_check "scrypt enc stdout flush failure"
		echo "-1" > "${c_exitfile}"
		setup_check "scrypt enc stdout flush error"
		echo "-1" > "${c_exitfile}"
		return
	fi

	# Keep the output small enough that the write error is delayed until
	# fclose(3) or fflush(3), rather than being returned by fwrite(3).
	printf "x" > "${input_file}"

	# A delayed failure while closing a named output file must fail the
	# command, rather than merely printing a warning and exiting 0.
	setup_check "scrypt enc named output close failure"
	printf "%s\n" "${password}" | "${bindir}/scrypt"		\
	    enc --logN 10 -r 1 -p 1				\
	    --passphrase dev:stdin-once				\
	    "${input_file}" /dev/full 2> "${named_stderr}"
	expected_exitcode 1 $? > "${c_exitfile}"

	setup_check "scrypt enc named output close error"
	grep -q "Error writing file: /dev/full" "${named_stderr}"
	echo $? > "${c_exitfile}"

	# stdout also needs an explicit flush check; exit(3) cannot propagate a
	# delayed stdio error into the process exit status.
	setup_check "scrypt enc stdout flush failure"
	printf "%s\n" "${password}" | "${bindir}/scrypt"		\
	    enc --logN 10 -r 1 -p 1				\
	    --passphrase dev:stdin-once				\
	    "${input_file}" > /dev/full 2> "${stdout_stderr}"
	expected_exitcode 1 $? > "${c_exitfile}"

	setup_check "scrypt enc stdout flush error"
	grep -q "Error writing file: standard output" "${stdout_stderr}"
	echo $? > "${c_exitfile}"
}
