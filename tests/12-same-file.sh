#!/bin/sh

### Constants
c_valgrind_min=1
reference_file="${scriptdir}/verify-strings/test_scrypt.good"
encrypted_reference_file="${scriptdir}/verify-strings/test_scrypt_good.enc"
plaintext_target="${s_basename}-plaintext.txt"
encrypted_target="${s_basename}-encrypted.enc"
normal_output="${s_basename}-normal.enc"
stderr_enc="${s_basename}-enc.stderr"
stderr_dec="${s_basename}-dec.stderr"

scenario_cmd() {
	# "scrypt enc" must not write into the file it is reading; opening
	# the output file truncates it.
	cp "${reference_file}" "${plaintext_target}"

	setup_check "scrypt enc same file"
	(
		echo "${password}" | ${c_valgrind_cmd} "${bindir}/scrypt" \
		    enc --passphrase dev:stdin-once			\
		    "${plaintext_target}" "${plaintext_target}"		\
		    2> "${stderr_enc}"
		expected_exitcode 1 $? > "${c_exitfile}"
	)

	setup_check "scrypt enc same file error"
	grep -q "scrypt: Input and output files are the same"		\
	    "${stderr_enc}"
	echo $? > "${c_exitfile}"

	setup_check "scrypt enc same file leaves input alone"
	cmp -s "${plaintext_target}" "${reference_file}"
	echo $? > "${c_exitfile}"

	# The same applies to "scrypt dec".
	cp "${encrypted_reference_file}" "${encrypted_target}"

	setup_check "scrypt dec same file"
	(
		echo "${password}" | ${c_valgrind_cmd} "${bindir}/scrypt" \
		    dec --passphrase dev:stdin-once			\
		    "${encrypted_target}" "${encrypted_target}"		\
		    2> "${stderr_dec}"
		expected_exitcode 1 $? > "${c_exitfile}"
	)

	setup_check "scrypt dec same file error"
	grep -q "scrypt: Input and output files are the same"		\
	    "${stderr_dec}"
	echo $? > "${c_exitfile}"

	setup_check "scrypt dec same file leaves input alone"
	cmp -s "${encrypted_target}" "${encrypted_reference_file}"
	echo $? > "${c_exitfile}"

	# Writing to a different file must still work.
	setup_check "scrypt enc different file"
	echo "${password}" | ${c_valgrind_cmd} "${bindir}/scrypt"	\
	    enc --passphrase dev:stdin-once				\
	    "${plaintext_target}" "${normal_output}"
	echo $? > "${c_exitfile}"
}
