package parser

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"Locker/internal/locker"
)

const (
	helpFlag           = "-h"
	positionalArgsNum  = 1 // only one file or directory path
	subcommandPosition = 1
	// default args value
	defaultOverwriteWithGarbagePasses = 1
	defaultConcurrency                = 7
)

type CmdArgs struct {
	Help                     bool
	Mode                     string
	Path                     string
	ProcessSubdirRecursively bool
	Concurrency              int
	LockArgs                 lockModeArgs
	UnlockArgs               unlockModeArgs
}

type lockModeArgs struct {
	SkipValidatePassphrase     bool
	OverwriteWithGarbagePasses int
	ForceToLock                bool
	KeepAfterLock              bool
	LockAsText                 bool
}

type unlockModeArgs struct {
	KeepAfterUnlock bool
	UnlockAsText    bool
}

func parseLockModeArgs() (CmdArgs, error) {
	var args CmdArgs
	args.Mode = locker.LockMode

	fs := flag.NewFlagSet(locker.LockMode, flag.ContinueOnError)

	// general args using by both lock and unlock mode
	fs.BoolVar(&args.ProcessSubdirRecursively, "r", false, "process subdirectories recursively")
	fs.IntVar(&args.Concurrency, "con", defaultConcurrency, "maximum number of concurrency locking/unlocking tasks")
	// lock mode args
	fs.BoolVar(&args.LockArgs.SkipValidatePassphrase, "skip-val", false, "skip validate the passphrase")
	fs.IntVar(&args.LockArgs.OverwriteWithGarbagePasses, "overwrite", defaultOverwriteWithGarbagePasses, "set number of passes to overwrite with garbage data")
	fs.BoolVar(&args.LockArgs.ForceToLock, "f", false, "force to lock locked files when processing directory")
	fs.BoolVar(&args.LockArgs.KeepAfterLock, "keep", false, "keep the original file after locking")
	fs.BoolVar(&args.LockArgs.LockAsText, "text", false, "print encrypted file content to the console as hex")

	fs.Parse(os.Args[subcommandPosition+1:])

	positionalArgs := fs.Args()
	if len(positionalArgs) != positionalArgsNum {
		return CmdArgs{}, fmt.Errorf("usage: locker lock [flags] [path]")
	}

	// file or directory path
	args.Path = positionalArgs[0]

	return args, nil
}

func parseUnlockArgs() (CmdArgs, error) {
	var args CmdArgs
	args.Mode = locker.UnlockMode

	fs := flag.NewFlagSet(locker.UnlockMode, flag.ContinueOnError)

	// general args using by both lock and unlock mode
	fs.BoolVar(&args.ProcessSubdirRecursively, "r", false, "process subdirectories recursively")
	fs.IntVar(&args.Concurrency, "con", defaultConcurrency, "maximum number of concurrency locking/unlocking tasks")
	// unlock mode args
	fs.BoolVar(&args.UnlockArgs.KeepAfterUnlock, "keep", false, "keep the locked file after unlocking")
	fs.BoolVar(&args.UnlockArgs.UnlockAsText, "text", false, "just show the file content not write to a new file")

	fs.Parse(os.Args[subcommandPosition+1:])

	positionalArgs := fs.Args()
	if len(positionalArgs) != positionalArgsNum {
		return CmdArgs{}, fmt.Errorf("usage: locker unlock [flags] [path]")
	}

	// file or directory path
	args.Path = positionalArgs[0]

	return args, nil
}

func ParseArgs() (CmdArgs, error) {
	if len(os.Args) == 1 {
		return CmdArgs{}, errors.New("usage: locker -h")
	}

	mode := os.Args[subcommandPosition]
	switch mode {
	case locker.LockMode:
		return parseLockModeArgs()
	case locker.UnlockMode:
		return parseUnlockArgs()
	case helpFlag:
		return CmdArgs{Help: true}, nil
	default:
		return CmdArgs{}, fmt.Errorf("invalid mode: %s", mode)
	}
}
