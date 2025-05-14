Vagrant.configure("2") do |config|
    config.vm.box = "boxen/archlinux-rolling"
    config.vm.synced_folder ".", "/vagrant", type: "rsync", rsync__exclude: ".git/"
    config.vm.provider :libvirt do |libvirt|
        # Enable forwarding of forwarded_port with id 'ssh'.
        libvirt.forward_ssh_port = true
    end
    config.vm.provision "shell", inline: <<-SHELL
        mount --make-private /
        cp -r /home/vagrant/.ssh /root
        cp /vagrant/config.toml /etc/pam_isolate.toml
        cp /vagrant/target/debug/libpam_isolate.so /lib64/security/pam_isolate.so
        cp /vagrant/target/debug/wrapns /usr/local/bin/
        chmod +s /usr/local/bin/wrapns
        echo "session [success=1 default=ignore] pam_succeed_if.so quiet uid eq 0" >> /etc/pam.d/sshd
        echo "session required pam_isolate.so --config /etc/pam_isolate.toml --log-level DEBUG" >> /etc/pam.d/sshd
    SHELL
end
