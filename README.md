# pam_isolate

A PAM module to lock users into cgroups/namespaces on (interactive) logins.
This makes it easy to restrict resource usage, monitor resource usage, and
prevent crosstalk between users.

1. [Install rustc](https://www.rust-lang.org/tools/install)
1. [Install Vagrant](https://developer.hashicorp.com/vagrant/downloads)
1. run `make`
1. run `make vm`

Log into the box using `vagrant ssh` and log into any user:

```shell
[vagrant@archlinux ~]$ su vagrant
Password:
Hello World!
[vagrant@archlinux ~]$
```

## Tests

1. install [shellinspector](https://github.com/Uberspace/shellinspector)
1. `make test`

## Notes

- You need to run `mount --make-private /` after every reboot to make
    mount namespaces work.
