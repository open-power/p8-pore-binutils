#source: empty-address-2.s
#ld: -Ttext 0x0000000 -Tdata 0x2000000 -T empty-address-2a.t
#nm: -n
#notarget: frv-*-*linux* *-*-linux*aout *-*-linux*oldld
#...
0+0 T _start
#...
0+10 A __data_end
#pass