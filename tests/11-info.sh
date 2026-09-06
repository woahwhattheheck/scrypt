#!/bin/sh

### Constants
c_valgrind_min=1
encrypted_reference_file="${scriptdir}/verify-strings/test_scrypt_good.enc"
bad_logN_file="${scriptdir}/verify-strings/test_scrypt_bad_logN.enc"
info_stderr="${s_basename}-info.stderr"
bad_logN_stderr="${s_basename}-bad-logN.stderr"

scenario_cmd() {
	# Print the parameters of a reference file.
	setup_check "scrypt info"
	${c_valgrind_cmd} "${bindir}/scrypt"				\
	    info "${encrypted_reference_file}"				\
	    2> "${info_stderr}"
	echo $? > "${c_exitfile}"

	# The reference file was encrypted with N = 2^18, r = 8, p = 1.
	setup_check "scrypt info output Nrp"
	grep -q "N = 262144; r = 8; p = 1;" "${info_stderr}"
	echo $? > "${c_exitfile}"

	# A header claiming logN = 255 must be rejected; computing N = 2^logN
	# would otherwise be an out-of-range shift.
	setup_check "scrypt info bad logN"
	(
		${c_valgrind_cmd} "${bindir}/scrypt"			\
		    info "${bad_logN_file}"				\
		    2> "${bad_logN_stderr}"
		expected_exitcode 1 $? > "${c_exitfile}"
	)

	setup_check "scrypt info bad logN error"
	grep -q "scrypt: Input is not valid scrypt-encrypted block"	\
	    "${bad_logN_stderr}"
	echo $? > "${c_exitfile}"
}