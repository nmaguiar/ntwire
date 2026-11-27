package wstransport

import (
	"testing"
	"time"
)

func TestQueuePerformance_SampledDelta(t *testing.T) {
	b := NewServer()
	if b.QueuePerformance().Enabled {
		t.Fatal("queue sampling was enabled by default")
	}
	b.EnableQueuePerformance()
	p := b.performance.Load()
	p.recordWrite(128 * time.Microsecond)
	before := b.QueuePerformance()
	batch := queuedBatch{datagrams: [][]byte{make([]byte, 16), make([]byte, 20)}, enqueued: time.Since(p.started) + 1}
	p.record(batch, 3)
	p.recordWrite(128 * time.Microsecond)
	b.Dropped.Add(1)
	sample := b.QueuePerformance().Delta(before)
	if sample == nil || sample.SampledBatches != 1 || sample.SampledDatagrams != 2 ||
		sample.SampledBytes != 36 || sample.DepthTotal != 3 || sample.DroppedBatches != 1 || sample.WriteDuration[8] != 1 {
		t.Fatalf("unexpected sample: %+v", sample)
	}
}

func TestQueuePerformance_PreservesQueueCapacity(t *testing.T) {
	for _, sampling := range []bool{false, true} {
		b := NewServer()
		if sampling {
			b.EnableQueuePerformance()
		}
		p := newPeer("benchmark", nil, endpoint{}, b.performance.Load())
		if sampling && (p.out != nil || p.sampled == nil) {
			t.Fatal("sampled peer should only use the sampled queue")
		}
		if !sampling && (p.out == nil || p.sampled != nil) {
			t.Fatal("default peer should only use the original queue")
		}
		for i := 0; i < peerQueueDepth; i++ {
			if p.enqueue([][]byte{{byte(i)}}) != queueAccepted {
				t.Fatal("queue rejected a packet inside its batch limit")
			}
		}
		if p.enqueue([][]byte{{0}}) != queueFull {
			t.Fatal("queue accepted a packet beyond its batch limit")
		}
		for i := 0; i < peerQueueDepth; i++ {
			queuedBatch, ok := p.nextBatch()
			batch := queuedBatch.datagrams
			if !ok || len(batch) != 1 || len(batch[0]) != 1 || batch[0][0] != byte(i) {
				t.Fatalf("queue changed packet order at index %d", i)
			}
		}
		sample := b.QueuePerformance()
		if sampling && sample.SampledBatches != peerQueueDepth/queueSampleEvery {
			t.Fatalf("recorded %d batches, want %d", sample.SampledBatches, peerQueueDepth/queueSampleEvery)
		}
	}
}
