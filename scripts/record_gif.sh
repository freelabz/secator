name=$1
castname=$1.cast
gifname=$1.gif

if [ !-f "$castname" ]; then
    RECORD=1 asciinema rec -c "env PS1=\"\$ \" /bin/bash --norc -i" $castname
fi

echo "Editing cast file to reduce long commands ..."
asciinema-edit quantize --range 4 $castname --out $castname.tmp
mv $castname.tmp $castname

echo "Generating GIF ..."
agg $castname $gifname
echo "GIF recording saved to $gifname"
