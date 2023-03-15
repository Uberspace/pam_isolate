Vagrant.configure("2") do |config|
    config.vm.box = "archlinux/archlinux"
    config.vm.provision "shell", inline: <<-SHELL
        cp /vargrant/config.toml /etc/pam_isolate.toml
        cp /vagrant/target/debug/libpam_isolate.so /lib64/security/pam_isolate.so
        echo "session [success=1 default=ignore] pam_succeed_if.so quiet uid eq 0" >> /etc/pam.d/su
        echo "session required pam_isolate.so --config /etc/pam_isolate.toml --log-level DEBUG" >> /etc/pam.d/su
    SHELL
end
