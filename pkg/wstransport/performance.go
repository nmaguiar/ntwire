package wstransport

import (
	"math/bits"
	"sync/atomic"
	"time"
)

const queueSampleEvery = 16

type queuedBatch struct {
	datagrams [][]byte
	enqueued  time.Duration // elapsed since the recorder started, plus one
}

// A peer only allocates timestamped queue entries when sampling is enabled.
type wssQueueBatch struct {
	datagrams [][]byte
	sampledAt time.Duration
}

type sampledPeerQueue struct {
	out      chan queuedBatch
	recorder *queuePerformance
}

func (q *sampledPeerQueue) next(done <-chan struct{}) (wssQueueBatch, bool) {
	select {
	case <-done:
		return wssQueueBatch{}, false
	case batch := <-q.out:
		if batch.enqueued != 0 {
			q.recorder.record(batch, len(q.out))
		}
		return wssQueueBatch{datagrams: batch.datagrams, sampledAt: batch.enqueued}, true
	}
}

func (q *sampledPeerQueue) enqueue(batch [][]byte, done <-chan struct{}) queueResult {
	queued := queuedBatch{datagrams: batch}
	if (q.recorder.sequence.Add(1)-1)%queueSampleEvery == 0 {
		queued.enqueued = time.Since(q.recorder.started) + 1
	}
	select {
	case <-done:
		return queueClosed
	case q.out <- queued:
		return queueAccepted
	default:
		return queueFull
	}
}

type queuePerformance struct {
	started   time.Time
	sequence  atomic.Uint64
	datagrams atomic.Uint64
	bytes     atomic.Uint64
	depth     atomic.Uint64
	residence [24]atomic.Uint64
	write     [24]atomic.Uint64
}

// QueuePerformance contains sampled WSS queue observations across all peers
// on a bind. QueueResidence bins are numbered by the bit length of elapsed
// microseconds, with sub-microsecond samples in bin zero and a final overflow bin.
type QueuePerformance struct {
	Enabled          bool       `json:"enabled"`
	SampleEvery      int        `json:"sample_every_batches"`
	SampledBatches   uint64     `json:"sampled_batches"`
	SampledDatagrams uint64     `json:"sampled_datagrams"`
	SampledBytes     uint64     `json:"sampled_ciphertext_bytes"`
	DepthTotal       uint64     `json:"sampled_queue_depth_total_batches"`
	QueueResidence   [24]uint64 `json:"queue_residence_log2_us"`
	WriteDuration    [24]uint64 `json:"write_duration_log2_us"`
	DroppedBatches   uint64     `json:"dropped_batches"`
}

// EnableQueuePerformance enables opt-in diagnostic sampling before opening
// the bind. Sampling affects only accounting, with no wire or queue changes.
func (b *Bind) EnableQueuePerformance() {
	b.performance.CompareAndSwap(nil, &queuePerformance{started: time.Now()})
}

func (b *Bind) QueuePerformance() QueuePerformance {
	p := b.performance.Load()
	if p == nil {
		return QueuePerformance{}
	}
	result := QueuePerformance{Enabled: true, SampleEvery: queueSampleEvery,
		SampledDatagrams: p.datagrams.Load(), SampledBytes: p.bytes.Load(), DepthTotal: p.depth.Load(), DroppedBatches: b.Dropped.Load()}
	for i := range result.QueueResidence {
		result.QueueResidence[i] = p.residence[i].Load()
		result.WriteDuration[i] = p.write[i].Load()
		result.SampledBatches += result.QueueResidence[i]
	}
	return result
}

func (result QueuePerformance) Delta(before QueuePerformance) *QueuePerformance {
	if !result.Enabled {
		return nil
	}
	result.SampledBatches -= min(result.SampledBatches, before.SampledBatches)
	result.SampledDatagrams -= min(result.SampledDatagrams, before.SampledDatagrams)
	result.SampledBytes -= min(result.SampledBytes, before.SampledBytes)
	result.DepthTotal -= min(result.DepthTotal, before.DepthTotal)
	result.DroppedBatches -= min(result.DroppedBatches, before.DroppedBatches)
	for i := range result.QueueResidence {
		result.QueueResidence[i] -= min(result.QueueResidence[i], before.QueueResidence[i])
		result.WriteDuration[i] -= min(result.WriteDuration[i], before.WriteDuration[i])
	}
	return &result
}

func (p *queuePerformance) recordWrite(elapsed time.Duration) {
	bin := bits.Len64(uint64(max(0, elapsed.Microseconds())))
	p.write[min(bin, len(p.write)-1)].Add(1)
}

func (p *queuePerformance) record(batch queuedBatch, depth int) {
	residence := time.Since(p.started) - (batch.enqueued - 1)
	elapsed := bits.Len64(uint64(max(0, residence.Microseconds())))
	var size int
	for _, datagram := range batch.datagrams {
		size += len(datagram)
	}
	p.bytes.Add(uint64(size))
	p.datagrams.Add(uint64(len(batch.datagrams)))
	p.depth.Add(uint64(depth))
	p.residence[min(elapsed, len(p.residence)-1)].Add(1)
}
