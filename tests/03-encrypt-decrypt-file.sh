#!/bin/sh

### Constants
c_valgrind_min=1
reference_file="${scriptdir}/verify-strings/test_scrypt.good"
encrypted_file="${s_basename}-attempt.enc"
decrypted_file="${s_basename}-attempt.txt"
same_file="${s_basename}-same.txt"
same_alias="${s_basename}-same-alias.txt"

scenario_cmd() {
	# Encrypt a file.  Use --passphrase dev:stdin-once instead of -P.
	setup_check "scrypt enc"
	(
		echo "${password}" | ${c_valgrind_cmd} "${bindir}/scrypt" \
		    enc --passphrase dev:stdin-once -t 1		\
		    "${reference_file}" "${encrypted_file}"
		echo $? > "${c_exitfile}"
	)

	# The encrypted file should be different from the original file.
	# We cannot check against the "reference" encrypted file, because
	# encrypted files include random salt.  If successful, don't delete
	# ${encrypted_file} yet; we need it for the next test.
	setup_check "scrypt enc random salt"
	cmp -s "${encrypted_file}" "${reference_file}"
	expected_exitcode 1 $? > "${c_exitfile}"

	# Decrypt the file we just encrypted.
	setup_check "scrypt enc decrypt"
	(
		echo "${password}" | ${c_valgrind_cmd} "${bindir}/scrypt" \
		    dec -P "${encrypted_file}" "${decrypted_file}"
		echo $? > "${c_exitfile}"
	)

	# The decrypted file should match the reference.
	setup_check "scrypt enc decrypt output against reference"
	cmp -s "${decrypted_file}" "${reference_file}"
	echo $? > "${c_exitfile}"

	# Refuse to overwrite a named input through the same pathname.
	cp "${reference_file}" "${same_file}"
	setup_check "scrypt enc rejects identical input and output"
	(
		echo "${password}" | ${c_valgrind_cmd} "${bindir}/scrypt" \
		    enc --passphrase dev:stdin-once -t 1		\
		    "${same_file}" "${same_file}"
		expected_exitcode 1 $? > "${c_exitfile}"
	)

	# A rejected same-file operation must leave the input untouched.
	setup_check "same input and output preserves input"
	cmp -s "${same_file}" "${reference_file}"
	echo $? > "${c_exitfile}"

	# Path-string comparison is insufficient: hard links name the same inode.
	ln "${same_file}" "${same_alias}"
	setup_check "scrypt enc rejects hard-linked output alias"
	(
		echo "${password}" | ${c_valgrind_cmd} "${bindir}/scrypt" \
		    enc --passphrase dev:stdin-once -t 1		\
		    "${same_file}" "${same_alias}"
		expected_exitcode 1 $? > "${c_exitfile}"
	)

	# The hard-linked input must also remain byte-for-byte intact.
	setup_check "hard-linked output rejection preserves input"
	cmp -s "${same_file}" "${reference_file}"
	echo $? > "${c_exitfile}"
}
