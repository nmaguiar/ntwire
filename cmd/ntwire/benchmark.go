package main

import (
	"github.com/nmaguiar/ntwire/internal/benchmark"
	"github.com/nmaguiar/ntwire/pkg/ui"
)

func benchmarkCmd(args []string, u *ui.UI) error {
	return benchmark.Command(args, u, nil)
}
