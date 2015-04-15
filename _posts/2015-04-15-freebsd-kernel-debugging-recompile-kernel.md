---
layout: post
title: "FreeBSD Kernel Debugging: Recompile Kernel"
description: ""
category: 
tags: []
---
{% include JB/setup %}

{% highlight text %}
# uname -a
FreeBSD  8.0-RELEASE FreeBSD 8.0-RELEASE #0: Sat Nov 21 15:48:17 UTC 2009     root@almeida.cse.buffalo.edu:/usr/obj/usr/src/sys/GENERIC  i386

ee /etc/ssh/sshd_config
PermitRootLogin yes
PasswordAuthentication yes
/etc/rc.d/sshd restart

sockstat -4 -l

ee /etc/rc.conf
ifconfig_em0="inet 192.168.252.155 netmask 255.255.255.0"
defaultrouter="192.168.252.1"

shutdown -p now

cd /usr/src/sys/i386/conf/
cp GENERIC EXPKERNEL

makeoptions	DEBUG=-g		# Build kernel with gdb(1) debug symbols

options		GDB
options		DDB
options		KDB

/boot/device.hints
hint.sio.0.flags="0x90"

/etc/sysctl.conf
debug.kdb.current=ddb
debug.debugger_on_panic=1

cd /usr/src
make buildkernel KERNCONF=EXPKERNEL
make installkernel KERNCONF=EXPKERNEL
shutdown -r now
{% endhighlight %}