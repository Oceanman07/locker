package parser

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"Locker/internal/locker"
)

const (
	positionalArgsNum  = 1 // only one file or directory path
	subcommandPosition = 1
	// default args value
	defaultOverwriteWithGarbagePasses = 1
)

type CmdArgs struct {
	Mode                     string
	Path                     string
	ProcessSubdirRecursively bool
	LockArgs                 lockModeArgs
	UnlockArgs               unlockModeArgs
}

type lockModeArgs struct {
	SkipValidatePassphrase     bool
	OverwriteWithGarbagePasses int
	ForceToLock                bool
}

type unlockModeArgs struct {
	KeepAfterUnlock bool
}

func parseLockModeArgs() (CmdArgs, error) {
	var args CmdArgs
	args.Mode = locker.LockMode

	fs := flag.NewFlagSet(locker.LockMode, flag.ContinueOnError)

	// general args using by both lock and unlock mode
	fs.BoolVar(&args.ProcessSubdirRecursively, "r", false, "process subdirectories recursively")
	// lock mode args
	fs.BoolVar(&args.LockArgs.SkipValidatePassphrase, "skip-val", false, "skip validate the passphrase")
	fs.IntVar(&args.LockArgs.OverwriteWithGarbagePasses, "overwrite", defaultOverwriteWithGarbagePasses, "set number of passes to overwrite with garbage data")
	fs.BoolVar(&args.LockArgs.ForceToLock, "f", false, "force to lock locked files when processing directory")

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

	fs.BoolVar(&args.UnlockArgs.KeepAfterUnlock, "keep", false, "keep the locked file after unlocking")

	// general args using by both lock and unlock mode
	fs.BoolVar(&args.ProcessSubdirRecursively, "r", false, "process subdirectories recursively")

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
	if len(os.Args) < 3 {
		return CmdArgs{}, errors.New("usage: locker [mode] [flags] [path]")
	}

	mode := os.Args[subcommandPosition]
	switch mode {
	case locker.LockMode:
		return parseLockModeArgs()
	case locker.UnlockMode:
		return parseUnlockArgs()
	default:
		return CmdArgs{}, fmt.Errorf("invalid mode: %s", mode)
	}
}
