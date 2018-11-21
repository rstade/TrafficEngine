**Please do not use this as a script, but just as hints for the major steps required! These steps will modify significantly your system. I can and will not guarantee that everything is correct and works as expected (see also LICENSE)! Also some links may need to be updated according to your OS version **


I used the CERN repository

* yum-config-manager --add-repo http://linuxsoft.cern.ch/cern/centos/7/rt/CentOS-RT.repo

next two steps were necessary on my system, as a dependency was broken. I guess that will be resolved over time:

* wget http://repo1.dal.innoscale.net/centos/7.5.1804/cr/x86_64/Packages/linux-firmware-20180911-69.git85c5d90.el7.noarch.rpm
* yum --nogpgcheck localinstall linux-firmware*.rpm

installing the CERN rpm key:

* pushd /etc/pki/rpm-gpg/
* wget http://linuxsoft.cern.ch/cern/slc5X/i386/RPM-GPG-KEYs/RPM-GPG-KEY-cern
* popd

the most significant steps:

* yum groupinstall RealTime
* yum install kernel-rt-devel.x86_64

here we define the cores which should get isolated:
* echo "isolated_cores=1-5" > /etc/tuned/realtime-variables.conf

we save our current cmdline, before we call the tuning script
* cat /proc/cmdline > cmdline_before_tuning.txt
* tuned-adm profile realtime

now we restart, and hope everything went well
* shutdown -r now
