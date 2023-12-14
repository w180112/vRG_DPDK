set -ex

wget https://dl.fedoraproject.org/pub/epel/9/Everything/x86_64/Packages/e/epel-release-9-7.el9.noarch.rpm
rpm -Uvh epel-release*rpm

dnf --enablerepo=crb install protobuf-devel
dnf --enablerepo=devel install meson libconfig-devel protobuf-compiler
dnf install grpc grpc-cpp grpc-devel
dnf install python3-pyelftools
