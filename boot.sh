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
cd $path/lib/dpdk && meson $path/lib/dpdk_build || exit 1
cd $path/lib/dpdk_build
sudo ninja && sudo ninja install || exit 1
sudo ldconfig || exit 1
cd $path/lib/dpdk-kmods/linux/igb_uio
make || exit 1
cd $path/lib/libutil
autoreconf --install || exit 1
./configure || exit 1
make || exit 1
cd $path/src
make
cd $path