#!/bin/sh

### Constants
c_valgrind_min=1
reference_file="${scriptdir}/verify-strings/test_scrypt.good"
small_file="${s_basename}-small.txt"
small_enc="${s_basename}-small.enc"
large_file="${s_basename}-large.txt"
large_enc="${s_basename}-large.enc"
stderr_enc_close="${s_basename}-enc-close.stderr"
stderr_dec_close="${s_basename}-dec-close.stderr"
stderr_enc="${s_basename}-enc.stderr"
stderr_dec="${s_basename}-dec.stderr"

# Explicit parameters keep the key derivation cheap, and -f skips the
# resource checks, which would otherwise measure the CPU speed every time.
fast_params="-f --logN 10 -r 1 -p 1"

scenario_cmd() {
	# Build a tiny input whose ciphertext remains buffered until fclose(),
	# plus a large input which forces write failures inside the copy loops.
	printf 'x' > "${small_file}"
	i=0
	while [ "${i}" -lt 128 ]; do
		cat "${reference_file}"
		i=$((i + 1))
	done > "${large_file}"

	# Encrypt both inputs to writable files.  The tiny ciphertext gives the
	# decrypt close-error case a one-byte plaintext output.
	setup_check "scrypt enc small file"
	echo "${password}" | ${c_valgrind_cmd} "${bindir}/scrypt"	\
	    enc ${fast_params} --passphrase dev:stdin-once		\
	    "${small_file}" "${small_enc}"
	echo $? > "${c_exitfile}"

	setup_check "scrypt enc large file"
	echo "${password}" | ${c_valgrind_cmd} "${bindir}/scrypt"	\
	    enc ${fast_params} --passphrase dev:stdin-once		\
	    "${large_file}" "${large_enc}"
	echo $? > "${c_exitfile}"

	# The write-error paths need an output file which never accepts data.
	# /dev/full is not portable, so stop here if we don't have it.
	if ! [ -c /dev/full ] || ! [ -w /dev/full ]; then
		return
	fi

	# Small outputs fit in stdio's buffer, so the crypto loop can succeed and
	# the first write error can be reported only when fclose() flushes it.
	setup_check "scrypt enc close write error"
	(
		echo "${password}" | ${c_valgrind_cmd} "${bindir}/scrypt" \
		    enc ${fast_params} --passphrase dev:stdin-once	\
		    "${small_file}" /dev/full				\
		    2> "${stderr_enc_close}"
		expected_exitcode 1 $? > "${c_exitfile}"
	)

	setup_check "scrypt enc close write error message"
	grep -q "scrypt: Error writing file: /dev/full" "${stderr_enc_close}"
	echo $? > "${c_exitfile}"

	setup_check "scrypt dec close write error"
	(
		echo "${password}" | ${c_valgrind_cmd} "${bindir}/scrypt" \
		    dec -f --passphrase dev:stdin-once			\
		    "${small_enc}" /dev/full				\
		    2> "${stderr_dec_close}"
		expected_exitcode 1 $? > "${c_exitfile}"
	)

	setup_check "scrypt dec close write error message"
	grep -q "scrypt: Error writing file: /dev/full" "${stderr_dec_close}"
	echo $? > "${c_exitfile}"

	# Large outputs overflow stdio's buffer, so these exercise write failures
	# inside the encrypt and decrypt loops rather than at final close.
	setup_check "scrypt enc write error"
	(
		echo "${password}" | ${c_valgrind_cmd} "${bindir}/scrypt" \
		    enc ${fast_params} --passphrase dev:stdin-once	\
		    "${large_file}" /dev/full				\
		    2> "${stderr_enc}"
		expected_exitcode 1 $? > "${c_exitfile}"
	)

	setup_check "scrypt enc write error message"
	grep -q "scrypt: Error writing file: /dev/full" "${stderr_enc}"
	echo $? > "${c_exitfile}"

	setup_check "scrypt dec write error"
	(
		echo "${password}" | ${c_valgrind_cmd} "${bindir}/scrypt" \
		    dec -f --passphrase dev:stdin-once			\
		    "${large_enc}" /dev/full				\
		    2> "${stderr_dec}"
		expected_exitcode 1 $? > "${c_exitfile}"
	)

	setup_check "scrypt dec write error message"
	grep -q "scrypt: Error writing file: /dev/full" "${stderr_dec}"
	echo $? > "${c_exitfile}"
}
