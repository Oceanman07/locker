package parser

import "fmt"

func PrintHelp() {
	fmt.Println("usage: locker [mode] [options] [path]")
	fmt.Println()
	fmt.Println("modes:")
	fmt.Println("  lock             lock a single file or files in directory;")
	fmt.Println("  unlock           unlock a single file or files in directory;")
	fmt.Println()
	fmt.Println("general options:")
	fmt.Println("  -h               print this help msg;")
	fmt.Println("  -r               process recursively subdirectories when locking")
	fmt.Println("                   or unlocking files in a directory;")
	fmt.Println("  -con             maximum number of concurrecy locking/unlocking tasks;")
	fmt.Println()
	fmt.Println("lock mode options:")
	fmt.Println("  -f               force to lock every file including locked files")
	fmt.Println("                   when locking files in a directory;")
	fmt.Println("  --skip-val       skip validate the passphrase;")
	fmt.Println("  --overwrite num  the number of overwrite garbage passes before")
	fmt.Println("                   deleting the original file;")
	fmt.Println("  --keep           keep the original file after locking;")
	fmt.Println("  --text           lock file content and print to the console as hex instead")
	fmt.Println("                   of writing to a new file and keep the original file;")
	fmt.Println()
	fmt.Println("unlock mode options:")
	fmt.Println("  --keep           keep the locked file after unlocking;")
	fmt.Println("  --text           unlock file content and print to the console instead")
	fmt.Println("                   of writing to a new file and keep the locked file;")
}
