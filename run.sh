

cd ~/hw4

make clean; make 2> make-stderr.out
RunFile=./hw4

testCase=03

inFile=./testcases/case$testCase.in

outFile=out.out
golden_outFile=./testcases/case$testCase.out

if [ -f "$RunFile" ]; then

    echo "==================================="
    echo "=            Run hw4             ="
    echo "==================================="

    ./$RunFile $inFile $outFile 2> run-stderr.out

    echo "==================================="
    echo "=      Print run-stderr.out       ="
    echo "==================================="

    cat run-stderr.out


    echo "==================================="
    echo "=            Validate             ="
    echo "==================================="

    # ./validation $outFile $golden_outFile
    # rm $outFile

else

    echo "==================================="
    echo "=      Print make-stderr.out      ="
    echo "==================================="

    cat make-stderr.out    

fi


echo ""
echo ""
