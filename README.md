# pam_isolate

A PAM module to lock users into cgroups/namespaces on (interactive) logins.
This makes it easy to restrict resource usage, monitor resource usage, and
prevent crosstalk between users.

1. [Install rustc](https://www.rust-lang.org/tools/install)
2. [Install Vagrant](https://developer.hashicorp.com/vagrant/downloads)
3. run `make`
4. run `make vm`

Log into the box using `vagrant ssh` and log into any user:

```shell
[vagrant@archlinux ~]$ su vagrant
Password:
Hello World!
[vagrant@archlinux ~]$
```

## Tests

1. install [shellinspector](https://github.com/Uberspace/shellinspector)
2. `make test`
