#!/bin/bash

# Print script commands and exit on errors.
set -xe

# --- Mininet --- #
MININET_COMMIT="aa0176fce6fb718a03474f8719261b07b670d30d"  # 2022-Apr-02
git clone https://github.com/mininet/mininet mininet
cd mininet
git checkout ${MININET_COMMIT}
PATCH_DIR="${HOME}/patches"
patch -p1 < "${PATCH_DIR}/mininet-dont-install-python2-2022-apr.patch" || echo "Errors while attempting to patch mininet, but continuing anyway ..."
cd ..
# TBD: Try without installing openvswitch, i.e. no '-v' option, to see
# if everything still works well without it.
sudo ./mininet/util/install.sh -nw

find /usr/lib /usr/local $HOME/.local | sort > $HOME/usr-local-7-after-mininet-install.txt

# --- Tutorials --- #
git clone https://github.com/p4lang/tutorials
sudo mv tutorials /home/p4
sudo chown -R p4:p4 /home/p4/tutorials


sudo mkdir -p /home/p4/Desktop
sudo mv /home/${USER}/Desktop/* /home/p4/Desktop
sudo chown -R p4:p4 /home/p4/Desktop/

# Do this last!
sudo reboot
