//go:build linux

package server

import (
	"errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

const kernelCounterBuckets = 4

var kernelBucketNames = [kernelCounterBuckets]string{"0-127", "128-511", "512-1279", "1280+"}

type kernelCounters struct {
	counters *ebpf.Map
	links    []link.Link
}

func newKernelCounters(interfaceIndex int) (*kernelCounters, error) {
	counters, err := ebpf.NewMap(&ebpf.MapSpec{
		Name: "ntwire_sizes", Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 8, MaxEntries: 2 * kernelCounterBuckets,
	})
	if err != nil {
		return nil, err
	}
	k := &kernelCounters{counters: counters}
	for direction, attach := range []ebpf.AttachType{ebpf.AttachTCXIngress, ebpf.AttachTCXEgress} {
		if err := k.attach(interfaceIndex, direction, attach); err != nil {
			return nil, errors.Join(err, k.close())
		}
	}
	return k, nil
}

func (k *kernelCounters) attach(interfaceIndex, direction int, attach ebpf.AttachType) error {
	base := int32(direction * kernelCounterBuckets)
	// __sk_buff.len is its first u32. Use fixed per-CPU buckets and return
	// TCX_NEXT so other programs and the networking stack see the packet.
	instructions := asm.Instructions{
		asm.LoadMem(asm.R2, asm.R1, 0, asm.Word),
		asm.Mov.Imm(asm.R3, base),
		asm.JLT.Imm(asm.R2, 128, "count"),
		asm.Add.Imm(asm.R3, 1),
		asm.JLT.Imm(asm.R2, 512, "count"),
		asm.Add.Imm(asm.R3, 1),
		asm.JLT.Imm(asm.R2, 1280, "count"),
		asm.Add.Imm(asm.R3, 1),
		asm.StoreMem(asm.RFP, -4, asm.R3, asm.Word).WithSymbol("count"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.LoadMapPtr(asm.R1, k.counters.FD()),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "done"),
		asm.Mov.Imm(asm.R1, 1),
		asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R0, -1).WithSymbol("done"),
		asm.Return(),
	}
	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "ntwire_size", Type: ebpf.SchedCLS, AttachType: attach, License: "Dual MIT/GPL", Instructions: instructions,
	})
	if err != nil {
		return err
	}
	defer program.Close()
	attached, err := link.AttachTCX(link.TCXOptions{Interface: interfaceIndex, Program: program, Attach: attach})
	if err == nil {
		k.links = append(k.links, attached)
	}
	return err
}

func (k *kernelCounters) snapshot() [2][kernelCounterBuckets]uint64 {
	var result [2][kernelCounterBuckets]uint64
	for direction := range result {
		for bucket := range result[direction] {
			var counts []uint64
			index := uint32(direction*kernelCounterBuckets + bucket)
			if err := k.counters.Lookup(index, &counts); err == nil {
				for _, count := range counts {
					result[direction][bucket] += count
				}
			}
		}
	}
	return result
}

func (k *kernelCounters) close() error {
	var err error
	for _, l := range k.links {
		err = errors.Join(err, l.Close())
	}
	return errors.Join(err, k.counters.Close())
}
