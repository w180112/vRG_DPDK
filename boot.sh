sudo pip3 install meson
sudo pip3 install ninja

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

cd ./lib/dpdk-stable && meson ../dpdk-build
cd ../dpdk-build
ninja && ninja instal
ldconfig
cd ../libutil
make
cd ../../src
make
cd ..