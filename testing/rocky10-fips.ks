text
cdrom
lang en_US.UTF-8
keyboard us
timezone America/New_York --utc
network --bootproto=dhcp --device=link --activate
rootpw --lock
# Keep the checked-in template credential-free. Add a Kickstart `sshkey` command
# for this locked account in a private working copy before installation.
user --name=dkim-test --lock --groups=wheel
firewall --enabled --service=ssh
selinux --enforcing
bootloader --append="fips=1"
zerombr
clearpart --all --initlabel
autopart --type=lvm
shutdown

%packages
@^minimal-environment
openssh-server
qemu-guest-agent
sudo
%end

%post
systemctl enable sshd
systemctl enable qemu-guest-agent
%end
