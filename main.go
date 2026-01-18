package main

import (
	"fmt"

	"Locker/internal/fileutil"
	"Locker/internal/locker"
	"Locker/internal/parser"
)

func processLocking(args parser.CmdArgs, passphrase string) {
	if fileutil.IsRegularFile(args.Path) {
		result := locker.Lock(passphrase, args.Path, args.LockArgs.OverwriteWithGarbagePasses)
		fmt.Println("[+] Locked  ", result)
	} else {
		filePaths := fileutil.ListDir(args.Path, args.ProcessSubdirRecursively)

		var normalFiles []string
		if args.LockArgs.ForceToLock {
			normalFiles = filePaths
		} else {
			normalFiles = fileutil.FilterFiles(filePaths, false)
		}

		total := len(normalFiles)
		var count int
		for _, path := range normalFiles {
			count += 1
			result := locker.Lock(passphrase, path, args.LockArgs.OverwriteWithGarbagePasses)
			fmt.Printf("[%d/%d] Locked   %s\n", count, total, result)
		}
	}
}

func processUnlocking(args parser.CmdArgs, passphrase string) {
	if fileutil.IsRegularFile(args.Path) {
		result, ok := locker.Unlock(passphrase, args.Path, args.UnlockArgs.KeepAfterUnlock)
		if ok {
			fmt.Println("[+] Unlock  ", result)
		} else {
			fmt.Println(result)
		}
	} else {
		filePaths := fileutil.ListDir(args.Path, args.ProcessSubdirRecursively)
		encryptedFiles := fileutil.FilterFiles(filePaths, true)

		total := len(encryptedFiles)
		var count int
		for _, path := range encryptedFiles {
			result, ok := locker.Unlock(passphrase, path, args.UnlockArgs.KeepAfterUnlock)
			if ok {
				count += 1
				fmt.Printf("[%d/%d] Unlock   %s\n", count, total, result)
			} else {
				fmt.Println(result)
			}
		}
	}
}

func main() {
	args, err := parser.ParseArgs()
	if err != nil {
		fmt.Println(err)
		return
	}

	if args.Help {
		parser.PrintHelp()
		return
	}
	if !fileutil.IsExist(args.Path) {
		fmt.Println("[-] Path not found")
		return
	}
	if fileutil.IsRootPath(args.Path) {
		fmt.Println("[-] Cannot process root")
		return
	}

	fmt.Print("passphrase:")
	passphrase := locker.GetPassphrase()
	fmt.Println()

	if args.Mode == locker.LockMode {
		if !args.LockArgs.SkipValidatePassphrase {
			if !locker.IsValidPassphrase(passphrase) {
				fmt.Println("[-] Passphrase must contain at least lowercase, uppercase and 1 number")
				return
			}
		}

		// reconfirm passphrase
		fmt.Print("confirm: ")
		confirmPassphrase := locker.GetPassphrase()
		if confirmPassphrase != passphrase {
			fmt.Println("[-] Passphrases didn't match")
			return
		}
		fmt.Println()

		processLocking(args, passphrase)

	} else if args.Mode == locker.UnlockMode {
		processUnlocking(args, passphrase)
	}
}
