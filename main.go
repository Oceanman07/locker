package main

import (
	"fmt"

	"Locker/internal/fileutil"
	"Locker/internal/locker"
	"Locker/internal/parser"
)

func processLocking(args parser.CmdArgs, passphrase string) {
	if fileutil.IsRegularFile(args.Path) {
		result, err := locker.Lock(
			passphrase,
			args.Path,
			args.LockArgs.OverwriteWithGarbagePasses,
			args.LockArgs.KeepAfterLock,
			args.LockArgs.LockAsText,
		)
		if err != nil {
			fmt.Println(err.Error())
		} else {
			fmt.Println("[+] Locked  ", result)
		}

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
			result, err := locker.Lock(
				passphrase,
				path,
				args.LockArgs.OverwriteWithGarbagePasses,
				args.LockArgs.KeepAfterLock,
				args.LockArgs.LockAsText,
			)
			if err != nil {
				fmt.Println(err.Error())
			} else {
				fmt.Printf("[%d/%d] Locked   %s\n", count, total, result)
			}
		}
	}
}

func processUnlocking(args parser.CmdArgs, passphrase string) {
	if fileutil.IsRegularFile(args.Path) {
		result, err := locker.Unlock(
			passphrase,
			args.Path,
			args.UnlockArgs.KeepAfterUnlock,
			args.UnlockArgs.UnlockAsText,
		)
		if err != nil {
			fmt.Println(err.Error())
		} else {
			fmt.Println("[+] Unlocked  ", result)
		}

	} else {
		filePaths := fileutil.ListDir(args.Path, args.ProcessSubdirRecursively)
		encryptedFiles := fileutil.FilterFiles(filePaths, true)

		total := len(encryptedFiles)
		var count int
		for _, path := range encryptedFiles {
			result, err := locker.Unlock(
				passphrase,
				path,
				args.UnlockArgs.KeepAfterUnlock,
				args.UnlockArgs.UnlockAsText,
			)
			if err != nil {
				fmt.Println(err.Error())
			} else {
				fmt.Printf("[%d/%d] Unlock   %s\n", count, total, result)
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
				fmt.Println("[-] Passphrase must contain at least lowercase, uppercase, 1 number and 1 special char `/()_-+*&^%$#@!:.?[]|~;=`")
				return
			}
		}
		// reconfirm passphrase
		fmt.Print("confirm: ")
		confirmPassphrase := locker.GetPassphrase()
		if confirmPassphrase != passphrase {
			fmt.Println()
			fmt.Println("[-] Passphrases didn't match")
			return
		}
		fmt.Println()

		processLocking(args, passphrase)

	} else if args.Mode == locker.UnlockMode {
		processUnlocking(args, passphrase)
	}
}
