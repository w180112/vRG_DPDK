set -ex

dnf --enablerepo=devel install meson libconfig-devel
dnf install python3-pyelftools
