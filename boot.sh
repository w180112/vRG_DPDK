set -ex

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
pushd $path/lib/dpdk && meson $path/lib/dpdk_build
popd
pushd $path/lib/dpdk_build
sudo ninja && sudo ninja install
sudo ldconfig
popd
pushd $path/lib/dpdk-kmods/linux/igb_uio
make
popd
pushd $path/lib/libutil
autoreconf --install
./configure
make
popd
pushd $path/src
make
popd
pushd $path
sudo cp $path/build/vrg /usr/local/bin/
popd