Build instructions
------------------

```
cd support
autoconf
autoheader
cd ..
./configure --prefix=/home/irc --with-openssl
cd x86-64*
make install-server
vim ~irc/etc/ircd.conf
```

Example config:
```
M%ssl.irc.org%%Experimental server%6667%0PNX
P%%%%6697%%P%
P%%%%6667%%%
Y%12%90%%100%512000%1.1%2.1%
I%*@*%%%%12%%
```
