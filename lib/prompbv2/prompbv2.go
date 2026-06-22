// Package prompbv2 implements a hand-written Prometheus Remote Write 2.0 marshaler
// for use in VictoriaMetrics / vmagent.
//
// Spec: https://prometheus.io/docs/specs/prw/remote_write_spec_2_0/
// Proto: prometheus/prometheus prompb/io/prometheus/write/v2/types.proto
//
// Field numbers (as read from the canonical proto file):
//
//	Request:    symbols=4, timeseries=5  (fields 1-3 reserved)
//	TimeSeries: labels_refs=1, samples=2, histograms=3, exemplars=4, metadata=5  (field 6 reserved)
//	Sample:     value=1, timestamp=2, start_timestamp=3
//	Metadata:   type=1, help_ref=3, unit_ref=4  (field 2 reserved)
//	MetricType enum: UNSPECIFIED=0, COUNTER=1, GAUGE=2, HISTOGRAM=3, GAUGEHISTOGRAM=4,
//	                 SUMMARY=5, INFO=6, STATESET=7
//
// NOTE: TimeSeries.created_timestamp is NOT a top-level TimeSeries field in the proto.
// The spec plan's reference to created_timestamp=6 in TimeSeries is incorrect — field 6
// is reserved in the actual proto. Created timestamp lives in Sample.start_timestamp (field 3).
//
// Wire contract (PoC implementation):
//   - Content-Type: application/x-protobuf;proto=io.prometheus.write.v2.Request
//   - X-Prometheus-Remote-Write-Version: 2.0.0
//   - Body: Snappy-compressed protobuf (same framing as v1)
//   - symbols[0] MUST be "" (empty string)
//   - labels_refs: flat uint32 pairs [name_ref, value_ref, ...], sorted by label name
//   - Metadata TYPE populated from the global type registry when available
//
// This is a PoC emitter. The following are DEFERRED (not implemented):
//   - Reliability: sender-side consumption of X-Prometheus-Remote-Write-Written-Samples
//     / -Histograms / -Exemplars write-stats response headers (partial-write detection,
//     retry/backoff). This is the main reliability value of PRW 2.0 and is a follow-up TODO.
//   - HELP and UNIT metadata: help_ref and unit_ref are left as 0 (empty string ref).
//   - Histograms, exemplars: TimeSeries fields 3 and 4 are left empty.
//   - Interning correctness at scale and memory pooling.
//   - Per-URL type registries (PoC uses a single global registry).
package prompbv2

import (
	"encoding/binary"
	"math"
	"math/bits"
	"sync"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/prompb"
)

// GlobalTypeRegistry is a simple concurrent-safe registry of metric name → MetricType.
// It is populated by the metadata push path (UpdateTypeRegistry) and read by MarshalRequest.
//
// This is a PoC design: a single global registry is suitable for single-URL vmagent configs.
// A per-URL registry would be needed for multi-URL configs with different metadata; that is DEFERRED.
//
// TYPE-tracking assessment (§4b):
//   - The per-scrape type map IS available at tryPush (remotewrite.go:398) before timeseries
//     and metadata are separated (tryPushMetadataToRemoteStorages vs TryPushTimeSeries paths).
//   - After separation, the timeseries path has no direct access to the scrape metadata.
//   - This global registry bridges the gap: metadata updates it; timeseries reads it at emit.
//   - Feasibility for counter/gauge: FEASIBLE-AND-CHEAP (direct name match from __name__ label).
//   - Feasibility for histogram/summary: FEASIBLE with suffix stripping for standard suffixes
//     (_total, _bucket, _sum, _count, _created, _info). Non-standard suffixes emit UNKNOWN.
//   - Conflict handling: last-writer-wins (last scrape for that metric name wins).
//     Metrics created by relabeling/aggregation with no source TYPE emit UNKNOWN.
//   - Re-attach after relabeling: relabeling may rename __name__, breaking the registry lookup.
//     For the PoC, renamed metrics will emit UNKNOWN type — documented limitation.
var (
	globalTypeRegistryMu sync.RWMutex
	globalTypeRegistry   = make(map[string]prompb.MetricType)
)

// UpdateTypeRegistry updates the global metric name → type registry from a v1 Metadata slice.
// Called by the metadata push path before metadata and timeseries are separated.
// Thread-safe.
func UpdateTypeRegistry(mms []prompb.MetricMetadata) {
	if len(mms) == 0 {
		return
	}
	globalTypeRegistryMu.Lock()
	for i := range mms {
		mm := &mms[i]
		if mm.MetricFamilyName != "" && mm.Type != 0 {
			globalTypeRegistry[mm.MetricFamilyName] = mm.Type
		}
	}
	globalTypeRegistryMu.Unlock()
}

// lookupType returns the MetricType for the given metric name from the global registry.
// Thread-safe.
func lookupType(metricName string) prompb.MetricType {
	globalTypeRegistryMu.RLock()
	t := globalTypeRegistry[metricName]
	globalTypeRegistryMu.RUnlock()
	return t
}

// SymbolsTable interns strings into a flat slice.
// symbols[0] is always "" (required by PRW v2 spec).
type SymbolsTable struct {
	symbols []string
	index   map[string]uint32
}

// newSymbolsTable returns a fresh SymbolsTable with the mandatory empty-string sentinel at index 0.
func newSymbolsTable() *SymbolsTable {
	return &SymbolsTable{
		symbols: []string{""},
		index:   map[string]uint32{"": 0},
	}
}

// intern interns s and returns its index.
func (st *SymbolsTable) intern(s string) uint32 {
	if idx, ok := st.index[s]; ok {
		return idx
	}
	idx := uint32(len(st.symbols))
	st.symbols = append(st.symbols, s)
	st.index[s] = idx
	return idx
}

// tsv2 holds the encoded per-TimeSeries data for the v2 wire format.
type tsv2 struct {
	labelsRefs []uint32
	metaType   prompb.MetricType
}

// MarshalRequest marshals the given v1 WriteRequest into PRW v2 wire format.
//
// The output is a raw protobuf byte slice (not yet snappy-compressed).
// Caller must snappy-compress before sending.
//
// Labels MUST already be sorted by name before calling (ensured by -sortLabels or
// the caller); PRW v2 requires labels_refs to be sorted by label name.
//
// TYPE metadata is looked up from the global registry (populated by UpdateTypeRegistry).
func MarshalRequest(wr *prompb.WriteRequest) []byte {
	st := newSymbolsTable()

	// First pass: build the symbols table and collect per-TimeSeries label refs + types.
	tsEncs := make([]tsv2, len(wr.Timeseries))
	for i := range wr.Timeseries {
		ts := &wr.Timeseries[i]
		refs := make([]uint32, 0, len(ts.Labels)*2)
		for j := range ts.Labels {
			nameRef := st.intern(ts.Labels[j].Name)
			valRef := st.intern(ts.Labels[j].Value)
			refs = append(refs, nameRef, valRef)
		}
		tsEncs[i].labelsRefs = refs

		// Resolve TYPE from the global registry.
		// Also try inline wr.Metadata (v1 separate metadata path may not yet have run;
		// the global registry is the primary source after the first scrape cycle).
		metricName := metricNameFromLabels(ts.Labels)
		if metricName != "" {
			// Try direct name lookup in global registry first.
			if t := lookupType(metricName); t != 0 {
				tsEncs[i].metaType = t
			} else if base := stripMetricSuffix(metricName); base != "" {
				// Try suffix-stripped base name (for histogram/summary components).
				if t := lookupType(base); t != 0 {
					tsEncs[i].metaType = t
				}
			}
			// Also check inline wr.Metadata (for the first flush when registry may be empty).
			if tsEncs[i].metaType == 0 && len(wr.Metadata) > 0 {
				tsEncs[i].metaType = lookupTypeInline(wr.Metadata, metricName)
			}
		}
	}

	// Second pass: encode the full PRW v2 request.
	// Field 4 (symbols): repeated string
	// Field 5 (timeseries): repeated TimeSeries
	buf := make([]byte, 0, 1024)
	syms := st.symbols
	for _, s := range syms {
		buf = appendTag(buf, 4, 2) // field 4, wire type 2 (length-delimited)
		buf = appendBytes(buf, []byte(s))
	}
	for i := range wr.Timeseries {
		ts := &wr.Timeseries[i]
		enc := &tsEncs[i]
		tsBytes := marshalTimeSeries(ts, enc)
		buf = appendTag(buf, 5, 2) // field 5, wire type 2
		buf = appendBytes(buf, tsBytes)
	}
	return buf
}

// lookupTypeInline looks up the type for metricName in the given metadata slice (inline fallback).
func lookupTypeInline(mms []prompb.MetricMetadata, metricName string) prompb.MetricType {
	for i := range mms {
		mm := &mms[i]
		if mm.MetricFamilyName == metricName && mm.Type != 0 {
			return mm.Type
		}
	}
	if base := stripMetricSuffix(metricName); base != "" {
		for i := range mms {
			mm := &mms[i]
			if mm.MetricFamilyName == base && mm.Type != 0 {
				return mm.Type
			}
		}
	}
	return 0
}

// metricNameFromLabels returns the __name__ label value.
func metricNameFromLabels(labels []prompb.Label) string {
	for i := range labels {
		if labels[i].Name == "__name__" {
			return labels[i].Value
		}
	}
	return ""
}

// stripMetricSuffix strips known Prometheus metric name suffixes to get the family name.
// Returns "" if no known suffix is found.
// Covers gauge/counter (direct match or _total) and histogram/summary suffixes.
func stripMetricSuffix(name string) string {
	suffixes := []string{
		"_total",
		"_bucket",
		"_sum",
		"_count",
		"_created",
		"_info",
	}
	for _, sfx := range suffixes {
		if len(name) > len(sfx) && name[len(name)-len(sfx):] == sfx {
			return name[:len(name)-len(sfx)]
		}
	}
	return ""
}

func marshalTimeSeries(ts *prompb.TimeSeries, enc *tsv2) []byte {
	var dst []byte

	// Field 1 (labels_refs): repeated uint32 (packed)
	// PRW v2 spec: labels_refs uses packed encoding.
	if len(enc.labelsRefs) > 0 {
		packedSize := 0
		for _, ref := range enc.labelsRefs {
			packedSize += sovUint(uint64(ref))
		}
		dst = appendTag(dst, 1, 2) // field 1, wire type 2 (packed)
		dst = appendVarint(dst, uint64(packedSize))
		for _, ref := range enc.labelsRefs {
			dst = appendVarint(dst, uint64(ref))
		}
	}

	// Field 2 (samples): repeated Sample
	for j := range ts.Samples {
		s := &ts.Samples[j]
		sBytes := marshalSample(s)
		dst = appendTag(dst, 2, 2)
		dst = appendBytes(dst, sBytes)
	}

	// Field 5 (metadata): Metadata — only if we have a non-zero type
	if enc.metaType != 0 {
		mBytes := marshalMetadata(enc.metaType)
		dst = appendTag(dst, 5, 2)
		dst = appendBytes(dst, mBytes)
	}

	return dst
}

func marshalSample(s *prompb.Sample) []byte {
	var dst []byte
	// Field 1 (value): double (fixed64, wire type 1)
	if s.Value != 0 {
		dst = appendTag(dst, 1, 1) // wire type 1 = 64-bit
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], math.Float64bits(s.Value))
		dst = append(dst, buf[:]...)
	}
	// Field 2 (timestamp): int64 (varint, wire type 0)
	if s.Timestamp != 0 {
		dst = appendTag(dst, 2, 0)
		dst = appendVarint(dst, uint64(s.Timestamp))
	}
	// start_timestamp (field 3) left as 0 (DEFERRED).
	return dst
}

func marshalMetadata(t prompb.MetricType) []byte {
	var dst []byte
	// Field 1 (type): MetricType enum (varint)
	if t != 0 {
		dst = appendTag(dst, 1, 0)
		dst = appendVarint(dst, uint64(t))
	}
	// help_ref (field 3) and unit_ref (field 4) left as 0 (deferred).
	return dst
}

func appendTag(dst []byte, fieldNum uint32, wireType uint32) []byte {
	return appendVarint(dst, uint64((fieldNum<<3)|wireType))
}

func appendVarint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

func appendBytes(dst []byte, b []byte) []byte {
	dst = appendVarint(dst, uint64(len(b)))
	return append(dst, b...)
}

func sovUint(x uint64) int {
	return (bits.Len64(x|1) + 6) / 7
}
