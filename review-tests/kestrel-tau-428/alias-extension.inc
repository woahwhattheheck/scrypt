
	# Extended static-alias coverage. This block belongs inside scenario_cmd.
	alias_password="${s_basename}-alias-password.txt"
	printf '%s\n' "${password}" > "${alias_password}"
	for alias_mode in enc dec; do
		alias_params=""
		alias_reference="${encrypted_reference_file}"
		if [ "${alias_mode}" = enc ]; then
			alias_params="--logN 10 -r 1 -p 1"
			alias_reference="${reference_file}"
		fi
		for alias_kind in hardlink output-symlink input-symlink stdin dotdot; do
			alias_input="${s_basename}-${alias_mode}-${alias_kind}-input"
			alias_link="${s_basename}-${alias_mode}-${alias_kind}-link"
			alias_stderr="${s_basename}-${alias_mode}-${alias_kind}.stderr"
			cp "${alias_reference}" "${alias_input}"
			alias_source="${alias_input}"
			alias_dest="${alias_link}"
			case "${alias_kind}" in
			hardlink)
				ln "${alias_input}" "${alias_link}"
				;;
			output-symlink)
				ln -s "${alias_input}" "${alias_link}"
				;;
			input-symlink)
				ln -s "${alias_input}" "${alias_link}"
				alias_source="${alias_link}"
				alias_dest="${alias_input}"
				;;
			stdin)
				alias_source="-"
				alias_dest="${alias_input}"
				;;
			dotdot)
				alias_dir="${s_basename}-${alias_mode}-${alias_kind}-dir"
				mkdir "${alias_dir}"
				alias_dest="${alias_dir}/../$(basename "${alias_input}")"
				;;
			esac

			setup_check "scrypt ${alias_mode} ${alias_kind} rejects alias"
			${c_valgrind_cmd} "${bindir}/scrypt" "${alias_mode}" \
			    ${alias_params} --passphrase file:"${alias_password}" \
			    "${alias_source}" "${alias_dest}" \
			    < "${alias_input}" 2> "${alias_stderr}"
			expected_exitcode 1 $? > "${c_exitfile}"

			setup_check "scrypt ${alias_mode} ${alias_kind} error"
			grep -q "scrypt: Input and output files are the same" \
			    "${alias_stderr}"
			echo $? > "${c_exitfile}"

			setup_check "scrypt ${alias_mode} ${alias_kind} preserves input"
			cmp -s "${alias_input}" "${alias_reference}"
			echo $? > "${c_exitfile}"
		done
	done

	# A character device is not a destructive same-regular-file alias.
	setup_check "scrypt enc permits same null device"
	${c_valgrind_cmd} "${bindir}/scrypt" enc --logN 10 -r 1 -p 1 \
	    --passphrase file:"${alias_password}" /dev/null /dev/null
	echo $? > "${c_exitfile}"

	# Equal contents are not the same inode; preserve and roundtrip the input.
	independent_input="${s_basename}-independent-input"
	independent_output="${s_basename}-independent-output"
	independent_plain="${s_basename}-independent-plain"
	cp "${reference_file}" "${independent_input}"
	cp "${reference_file}" "${independent_output}"
	setup_check "scrypt enc permits identical contents in independent files"
	${c_valgrind_cmd} "${bindir}/scrypt" enc --logN 10 -r 1 -p 1 \
	    --passphrase file:"${alias_password}" \
	    "${independent_input}" "${independent_output}"
	echo $? > "${c_exitfile}"

	setup_check "scrypt enc independent files preserves input"
	cmp -s "${independent_input}" "${reference_file}"
	echo $? > "${c_exitfile}"

	setup_check "scrypt dec independent output roundtrip"
	${c_valgrind_cmd} "${bindir}/scrypt" dec \
	    --passphrase file:"${alias_password}" \
	    "${independent_output}" "${independent_plain}"
	echo $? > "${c_exitfile}"

	setup_check "scrypt dec independent output matches input"
	cmp -s "${independent_plain}" "${reference_file}"
	echo $? > "${c_exitfile}"
