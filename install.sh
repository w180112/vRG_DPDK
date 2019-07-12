get_script_dir () {
	SOURCE="${BASH_SOURCE[0]}"
	# While $SOURCE is a symlink, resolve it
	while [ -h "$SOURCE" ]; do
		DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
		SOURCE="$( readlink "$SOURCE" )" 
		# If $SOURCE was a relative symlink (so no "/" as prefix, need to resolve it relative to the symlink base directory
		[[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
	done
	DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
	echo "$DIR"
}

export RTE_SDK=$(get_script_dir)/src/lib/dpdk-stable-18.11.2 
export RTE_TARGET=x86_64-native-linuxapp-gcc
cd ./src
make
cd ..