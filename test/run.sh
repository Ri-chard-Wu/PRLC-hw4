

cd ~/hw4/test

make clean; make 2> make-stderr.out
RunFile=./main


if [ -f "$RunFile" ]; then

    echo "==================================="
    echo "=            Run hw3             ="
    echo "==================================="

    ./$RunFile > run-stderr.out

    echo "==================================="
    echo "=      Print run-stderr.out       ="
    echo "==================================="

    cat run-stderr.out

else

    echo "==================================="
    echo "=      Print make-stderr.out      ="
    echo "==================================="

    cat make-stderr.out    

fi


echo ""
echo ""
