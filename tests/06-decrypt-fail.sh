#!/bin/sh

### Constants
c_valgrind_min=1
non_encoded_file="${scriptdir}/06-decrypt-fail.sh"
non_encoded_file_stderr="${s_basename}-stderr.txt"
non_encoded_file_output="${s_basename}-nonfile.txt"
encrypted_reference_file="${scriptdir}/verify-strings/test_scrypt_good.enc"
tampered_reference_file="${s_basename}-tampered.enc"
tampered_reference_stderr="${s_basename}-tampered.stderr"
tampered_reference_output="${s_basename}-tampered-output.txt"
tampered_reference_stdout="${s_basename}-tampered-stdout.txt"

scenario_cmd() {
	# Attempt to decrypt a non-scrypt-encoded file.
	# We want this command to fail with 1.
	setup_check "scrypt dec non-scrypt"
	(
		echo "" | ${c_valgrind_cmd} "${bindir}/scrypt"		\
		    dec -P "${non_encoded_file}"			\
		    "${non_encoded_file_output}"			\
			2>> "${non_encoded_file_stderr}"
		expected_exitcode 1 $? > "${c_exitfile}"
	)

	# We should have received an error message.
	setup_check "scrypt dec non-scrypt error"
	grep -q "scrypt: Input is not valid scrypt-encrypted block" \
	    "${non_encoded_file_stderr}"
	echo "$?" > "${c_exitfile}"

	# We should not have created a file.
	setup_check "scrypt dec non-scrypt no file"
	if [ -e "${non_encoded_file_output}" ]; then
		echo "1"
	else
		echo "0"
	fi > "${c_exitfile}"

	# Damage only the trailing authenticator of a valid encrypted fixture.
	# This preserves the header, passphrase check, and all encrypted payload
	# bytes while guaranteeing that full-stream authentication fails.
	setup_check "scrypt dec tampered authenticator fixture"
	tampered_size=$(wc -c < "${encrypted_reference_file}")
	dd if="${encrypted_reference_file}" of="${tampered_reference_file}" \
	    bs=1 count=$((tampered_size - 1)) 2>/dev/null
	echo "$?" > "${c_exitfile}"

	# A named-output decrypt must fail before the destination is opened.  In
	# particular, no unauthenticated plaintext may be written and no empty or
	# partial output artifact should be created.
	setup_check "scrypt dec tampered authenticator named output"
	(
		echo "${password}" | ${c_valgrind_cmd} "${bindir}/scrypt" \
		    dec -P "${tampered_reference_file}" \
		    "${tampered_reference_output}" \
		    2> "${tampered_reference_stderr}"
		expected_exitcode 1 $? > "${c_exitfile}"
	)

	setup_check "scrypt dec tampered authenticator named output no file"
	if [ -e "${tampered_reference_output}" ]; then
		echo "1"
	else
		echo "0"
	fi > "${c_exitfile}"

	setup_check "scrypt dec tampered authenticator error"
	grep -q "scrypt: Input is not valid scrypt-encrypted block" \
	    "${tampered_reference_stderr}"
	echo "$?" > "${c_exitfile}"

	# Standard output cannot be retracted.  It therefore must remain empty
	# until the encrypted stream's trailing authenticator has been verified.
	setup_check "scrypt dec tampered authenticator stdout"
	(
		echo "${password}" | ${c_valgrind_cmd} "${bindir}/scrypt" \
		    dec -P "${tampered_reference_file}" \
		    > "${tampered_reference_stdout}" 2>/dev/null
		expected_exitcode 1 $? > "${c_exitfile}"
	)

	setup_check "scrypt dec tampered authenticator stdout empty"
	if [ -s "${tampered_reference_stdout}" ]; then
		echo "1"
	else
		echo "0"
	fi > "${c_exitfile}"
}
