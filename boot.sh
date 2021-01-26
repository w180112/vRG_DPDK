get_script_dir () {
     SOURCE="${BASH_SOURCE[0]}"
     while [ -h "$SOURCE" ]; do
          DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
          SOURCE="$( readlink "$SOURCE" )" 
          [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
     done
     DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
     echo "$DIR"
}
path=$(get_script_dir)
cd $path/lib/dpdk && meson $path/lib/dpdk_build
cd $path/lib/dpdk_build
ninja && sudo ninja install
ldconfig
cd $path/lib/libutil
make
cd $path/src
make
cd $path