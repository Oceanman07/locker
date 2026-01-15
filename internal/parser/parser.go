package parser

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

const (
	lockMode           = "lock"
	unlockMode         = "unlock"
	positionalArgsNum  = 1 // only one file or directory path
	subcommandPosition = 1
	// default args value
	defaultOverwriteWithGarbagePasses = 1
)

type CmdArgs struct {
	Mode       string
	Path       string
	LockArgs   lockModeArgs
	UnlockArgs unlockModeArgs
}

type lockModeArgs struct {
	SkipValidatePassphrase     bool
	OverwriteWithGarbagePasses int
}

type unlockModeArgs struct{}

func parseLockModeArgs() (CmdArgs, error) {
	var args CmdArgs
	args.Mode = lockMode

	fs := flag.NewFlagSet(lockMode, flag.ContinueOnError)

	fs.BoolVar(&args.LockArgs.SkipValidatePassphrase, "skip-val", false, "enable to skip validate the passphrase")
	fs.IntVar(&args.LockArgs.OverwriteWithGarbagePasses, "overwrite", defaultOverwriteWithGarbagePasses, "set number of passes to overwrite with garbage data")

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
	args.Mode = unlockMode

	fs := flag.NewFlagSet(unlockMode, flag.ContinueOnError)

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
	case lockMode:
		return parseLockModeArgs()
	case unlockMode:
		return parseUnlockArgs()
	default:
		return CmdArgs{}, fmt.Errorf("invalid mode: %s", mode)
	}
}
