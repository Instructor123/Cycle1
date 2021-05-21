package main

import (
	"bufio"
	"cycle1/errorHandling"
	"cycle1/machoHeader"
	"fmt"
	"os"
	"strings"
)

func main(){

	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Please enter the file you want to analyze: ")
	fileName, err := reader.ReadString('\n')
	errorHandling.CheckErr(err)

	fileName = strings.Trim(fileName, "\n")

	myMachoFile := machoHeader.LoadStruct(fileName)

	myMachoFile.PrintStruct()

}
