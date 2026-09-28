package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"

	"Locker/internal/fileutil"
	"Locker/internal/locker"
	"Locker/internal/parser"
)

func lockRegularFile(args parser.CmdArgs, passphrase string) {
	result, err := locker.Lock(
		passphrase,
		args.Path,
		args.LockArgs.OverwriteWithGarbagePasses,
		args.LockArgs.KeepAfterLock,
		args.LockArgs.LockAsText,
	)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("[+] Locked  ", result)
}

func lockDirectory(args parser.CmdArgs, passphrase string) {
	// instead of let control+c kill the process -> cancel the context
	// the whole point is to keep processing task finish
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT)
	defer stop()

	semaphore := make(chan struct{}, args.Concurrency)
	var wg sync.WaitGroup

	filePaths := fileutil.ListDir(args.Path, args.ProcessSubdirRecursively)

	var normalFiles []string
	if args.LockArgs.ForceToLock {
		normalFiles = filePaths
	} else {
		normalFiles = fileutil.FilterFiles(filePaths, false)
	}

	total := len(normalFiles)
	var counter atomic.Int64
	for _, path := range normalFiles {
		wg.Add(1)

		go func() {
			defer wg.Done()
			// get a slot in semaphore, if semaphore is full then the current gorountine will wait
			semaphore <- struct{}{}
			// release to let the next gorountine join the semaphore
			defer func() { <-semaphore }()

			select {
			case <-ctx.Done():
				return
			default:
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
					counter.Add(1)
					fmt.Printf("[%d/%d] Locked   %s\n", counter.Load(), total, result)
				}
			}
		}()
	}

	wg.Wait()
}

func unlockRegularFile(args parser.CmdArgs, passphrase string) {
	result, err := locker.Unlock(
		passphrase,
		args.Path,
		args.UnlockArgs.KeepAfterUnlock,
		args.UnlockArgs.UnlockAsText,
	)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("[+] Unlocked  ", result)
}

func unlockDirectory(args parser.CmdArgs, passphrase string) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT)
	defer stop()

	semaphore := make(chan struct{}, args.Concurrency)
	var wg sync.WaitGroup

	filePaths := fileutil.ListDir(args.Path, args.ProcessSubdirRecursively)
	encryptedFiles := fileutil.FilterFiles(filePaths, true)

	total := len(encryptedFiles)
	var counter atomic.Int64
	for _, path := range encryptedFiles {
		wg.Add(1)

		go func() {
			defer wg.Done()
			// get a slot in semaphore, if semaphore is full then the current gorountine will wait
			semaphore <- struct{}{}
			// release to let the next gorountine join the semaphore
			defer func() { <-semaphore }()

			select {
			case <-ctx.Done():
				return
			default:
				result, err := locker.Unlock(
					passphrase,
					path,
					args.UnlockArgs.KeepAfterUnlock,
					args.UnlockArgs.UnlockAsText,
				)
				if err != nil {
					fmt.Println(err.Error())
				} else {
					counter.Add(1)
					fmt.Printf("[%d/%d] Unlock   %s\n", counter.Load(), total, result)
				}
			}
		}()
	}

	wg.Wait()
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
				fmt.Println("[-] Passphrase must contain at least 4 chars, lowercase, uppercase, 1 number and 1 special char `/()_-+*&^%$#@!:.?[]|~;=`")
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

		if fileutil.IsRegularFile(args.Path) {
			lockRegularFile(args, passphrase)
		} else {
			lockDirectory(args, passphrase)
		}

	} else if args.Mode == locker.UnlockMode {
		if fileutil.IsRegularFile(args.Path) {
			unlockRegularFile(args, passphrase)
		} else {
			unlockDirectory(args, passphrase)
		}
	}
}
