**Please do not use this as a script, but just as hints for the major steps required! These steps will modify significantly your system. I can and will not guarantee that everything is correct and works as expected (see also LICENSE)! Also some links may need to be updated according to your OS version. These steps worked for my Rocky Linux 8.5 system**

enable the realtime repository:

* dnf config-manager --set-enabled rt

the most significant step:

* dnf groupinstall RT

check for the default kernel:

* grubby --default-kernel

here we define the cores which should get isolated (numbering starts with 0):
* echo "isolated_cores=1-5" >> /etc/tuned/realtime-variables.conf

we save our current cmdline, before we call the tuning script
* cat /proc/cmdline > cmdline_before_tuning.txt
* tuned-adm profile realtime

now we restart, and hope everything went well
* shutdown -r now

after restarting we check for the running kernel:

* uname -a

and for the kernel cmdline:

* cat /proc/cmdline
