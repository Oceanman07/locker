package main

import (
	"context"
	"errors"
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

func lockRegularFile(args *parser.CmdArgs, passphrase string) {
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

func lockDirectory(args *parser.CmdArgs, passphrase string) {
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

		go func(path string) {
			defer wg.Done()
			// get a slot in semaphore, if semaphore is full then the current gorountine will wait
			semaphore <- struct{}{}
			// release to let the next gorountine join the semaphore
			defer func() { <-semaphore }()

			select {
			case <-ctx.Done():
				return
			default:
				// before args.Path is the directory path
				// after getting all the files in the directory
				// we process each file in there (path is now the file path to be processed)
				args.Path = path
				lockRegularFile(args, passphrase)

				num := counter.Add(1)
				fmt.Printf("[%d/%d] Locked files\n", num, total)
			}
		}(path)
	}

	wg.Wait()
}

func unlockRegularFile(args *parser.CmdArgs, passphrase string) {
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

func unlockDirectory(args *parser.CmdArgs, passphrase string) {
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

		go func(path string) {
			defer wg.Done()
			// get a slot in semaphore, if semaphore is full then the current gorountine will wait
			semaphore <- struct{}{}
			// release to let the next gorountine join the semaphore
			defer func() { <-semaphore }()

			select {
			case <-ctx.Done():
				return
			default:
				// before args.Path is the directory path
				// after getting all the files in the directory
				// we process each file in there (path is now the file path to be processed)
				args.Path = path
				unlockRegularFile(args, passphrase)

				num := counter.Add(1)
				fmt.Printf("[%d/%d] Unlocked files\n", num, total)
			}
		}(path)
	}

	wg.Wait()
}

func handleInputPassphrase(mode string) (string, error) {
	defer fmt.Println()
	fmt.Print("passphrase:")

	passphrase := locker.GetPassphrase()
	// when unlocking we just need the passphrase while locking needs to confirm again
	if mode == locker.UnlockMode {
		return passphrase, nil
	}

	// reconfirm passphrase when locking
	fmt.Print("\nconfirm: ")

	confirmPassphrase := locker.GetPassphrase()
	if confirmPassphrase == passphrase {
		return passphrase, nil
	}

	return "", locker.PassphraseNotMatchErr
}

func main() {
	args, err := parser.ParseArgs()
	if err != nil {
		if errors.Is(err, parser.InvalidCmdLengthErr) {
			parser.PrintHelp()
		} else {
			fmt.Println(err)
		}
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

	if args.Mode == locker.LockMode {
		passphrase, err := handleInputPassphrase(locker.LockMode)
		if err != nil {
			fmt.Println(err.Error())
			return
		}

		// checking/not checking for safety passphrase
		if !args.LockArgs.SkipValidatePassphrase && !locker.IsValidPassphrase(passphrase) {
			fmt.Println("[-] Passphrase must contain at least 4 chars, lowercase, uppercase, 1 number and 1 special char `/()_-+*&^%$#@!:.?[]|~;=`")
			return
		}

		if fileutil.IsRegularFile(args.Path) {
			lockRegularFile(&args, passphrase)
		} else {
			lockDirectory(&args, passphrase)
		}

	} else if args.Mode == locker.UnlockMode {
		passphrase, _ := handleInputPassphrase(locker.UnlockMode)

		if fileutil.IsRegularFile(args.Path) {
			unlockRegularFile(&args, passphrase)
		} else {
			unlockDirectory(&args, passphrase)
		}
	}
}
