#!/bin/sh

### Constants
c_valgrind_min=1
reference_file="${scriptdir}/verify-strings/test_scrypt.good"
encrypted_file="${s_basename}-attempt.enc"
decrypted_file="${s_basename}-attempt.txt"
nul_output="${s_basename}-nul-passphrase.txt"
nul_log="${s_basename}-nul-passphrase.log"
long_encrypted_file="${s_basename}-long-passphrase.enc"
long_decrypted_file="${s_basename}-long-passphrase.txt"
long_rejected_file="${s_basename}-long-passphrase-rejected.txt"
long_log="${s_basename}-long-passphrase.log"
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

	# A passphrase read from stdin is returned as a C string.  Reject an
	# embedded NUL rather than silently treating the following bytes as absent.
	setup_check "scrypt dec rejects NUL in stdin passphrase"
	(
		printf 'hunter2\000extra\n' |				\
		    ${c_valgrind_cmd} "${bindir}/scrypt" dec		\
		    --passphrase dev:stdin-once "${encrypted_file}"	\
		    "${nul_output}" 2> "${nul_log}"
		expected_exitcode 1 $? > "${c_exitfile}"
	)

	# The rejection should identify the input problem directly.
	setup_check "scrypt dec stdin NUL error"
	grep -q "scrypt: NUL byte in password" "${nul_log}"
	echo $? > "${c_exitfile}"

	# Password rejection happens before the output is opened.
	setup_check "scrypt dec stdin NUL no output"
	test -e "${nul_output}"
	expected_exitcode 1 $? > "${c_exitfile}"

	# Build a ciphertext protected by the longest password the reader accepts.
	# env: can supply the reference value without exercising the stdin reader.
	long_password=$(awk 'BEGIN { for (i = 0; i < 2047; i++) printf "A" }')
	setup_check "scrypt enc 2047-byte passphrase"
	(
		SCRYPT_LONG_PASSWORD="${long_password}" ${c_valgrind_cmd} \
		    "${bindir}/scrypt" enc --passphrase env:SCRYPT_LONG_PASSWORD \
		    -t 1 "${reference_file}" "${long_encrypted_file}"
		echo $? > "${c_exitfile}"
	)

	# Exactly 2047 password bytes followed by a newline remain valid.
	setup_check "scrypt dec accepts 2047-byte stdin passphrase"
	(
		printf '%s\n' "${long_password}" |			\
		    ${c_valgrind_cmd} "${bindir}/scrypt" dec		\
		    --passphrase dev:stdin-once "${long_encrypted_file}" \
		    "${long_decrypted_file}"
		echo $? > "${c_exitfile}"
	)

	setup_check "scrypt dec 2047-byte output against reference"
	cmp -s "${long_decrypted_file}" "${reference_file}"
	echo $? > "${c_exitfile}"

	# A longer line must not silently authenticate as its 2047-byte prefix.
	setup_check "scrypt dec rejects overlong stdin passphrase"
	(
		printf '%sX\n' "${long_password}" |			\
		    ${c_valgrind_cmd} "${bindir}/scrypt" dec		\
		    --passphrase dev:stdin-once "${long_encrypted_file}" \
		    "${long_rejected_file}" 2> "${long_log}"
		expected_exitcode 1 $? > "${c_exitfile}"
	)

	setup_check "scrypt dec overlong stdin error"
	grep -q "scrypt: Password is too long" "${long_log}"
	echo $? > "${c_exitfile}"

	setup_check "scrypt dec overlong stdin no output"
	test -e "${long_rejected_file}"
	expected_exitcode 1 $? > "${c_exitfile}"

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
