package sifter

import (
	"fmt"
	"math"

	"github.com/google/syzkaller/prog"
)

type ValueRangeAnalysis struct {
	argRanges map[*ArgMap][]uint64
	regRanges map[*Syscall][]uint64
	vlrRanges map[*VlrMap]map[*VlrRecord][]uint64
}

func (a *ValueRangeAnalysis) String() string {
	return "value range analysis"
}

func (a *ValueRangeAnalysis) Init(TracedSyscalls *map[string][]*Syscall) {
	a.argRanges = make(map[*ArgMap][]uint64)
	a.regRanges = make(map[*Syscall][]uint64)
	a.vlrRanges = make(map[*VlrMap]map[*VlrRecord][]uint64)
	for _, syscalls := range *TracedSyscalls {
		for _, syscall := range syscalls {
			for i := 0; i < 6; i++ {
				a.regRanges[syscall] = append(a.regRanges[syscall], math.MaxInt64)
				a.regRanges[syscall] = append(a.regRanges[syscall], 0)
			}
			for _, arg := range syscall.argMaps {
				if structArg, ok := arg.arg.(*prog.StructType); ok {
					for _, _ = range structArg.Fields {
						a.argRanges[arg] = append(a.argRanges[arg], math.MaxInt64)
						a.argRanges[arg] = append(a.argRanges[arg], 0)
					}
				} else {
					a.argRanges[arg] = append(a.argRanges[arg], math.MaxInt64)
					a.argRanges[arg] = append(a.argRanges[arg], 0)
				}
			}
			for _, vlr := range syscall.vlrMaps {
				a.vlrRanges[vlr] = make(map[*VlrRecord][]uint64)
				for _, record := range vlr.records {
					if structArg, ok := record.arg.(*prog.StructType); ok {
						for _, f := range structArg.Fields {
							if structField, ok := f.Type.(*prog.StructType); ok {
								for _, _ = range structField.Fields {
									a.vlrRanges[vlr][record] = append(a.vlrRanges[vlr][record], math.MaxInt64)
									a.vlrRanges[vlr][record] = append(a.vlrRanges[vlr][record], 0)
								}
							} else {
								a.vlrRanges[vlr][record] = append(a.vlrRanges[vlr][record], math.MaxInt64)
								a.vlrRanges[vlr][record] = append(a.vlrRanges[vlr][record], 0)
							}
						}
					}
				}
			}
		}
	}
}

func (a *ValueRangeAnalysis) Reset() {
}

func (a *ValueRangeAnalysis) ProcessTraceEvent(te *TraceEvent, flag AnalysisFlag, opt int) (string, int, int) {
	if te.typ != 1 {
		return "", 0, 0
	}

	if (te.flag & TraceEventFlagBadData) != 0 {
		return "", 0, 0
	}

	msgs := make([]string, 0)
	var offset uint64
	for i := 0; i < 6; i++ {
		if i < 1 {
		_, tr := te.GetData(offset, 8)
		if (a.regRanges[te.syscall][i*2+0] > tr) {
			if flag == TrainFlag {
				a.regRanges[te.syscall][i*2+0] = tr
			}
			msgs = append(msgs, fmt.Sprintf("reg[%v]:l %x", i, tr))
		}
		if (a.regRanges[te.syscall][i*2+1] < tr) {
			if flag == TrainFlag {
				a.regRanges[te.syscall][i*2+1] = tr
			}
			msgs = append(msgs, fmt.Sprintf("reg[%v]:u %x", i, tr))
		}
		}
		offset += 8
	}
	for _, arg := range te.syscall.argMaps {
		if structArg, ok := arg.arg.(*prog.StructType); ok {
			for i, field := range structArg.Fields {
				if _, isPtrArg := field.Type.(*prog.PtrType); !isPtrArg && field.Name != "ptr" {
					_, tr := te.GetData(offset, field.Size())
					if (a.argRanges[arg][2*i+0] > tr) {
						if flag == TrainFlag {
							a.argRanges[arg][2*i+0] = tr
						}
						msgs = append(msgs, fmt.Sprintf("%v:l %x", arg.name, tr))
					}
					if (a.argRanges[arg][2*i+1] < tr) {
						if flag == TrainFlag {
							a.argRanges[arg][2*i+1] = tr
						}
						msgs = append(msgs, fmt.Sprintf("%v:u %x", arg.name, tr))
					}
				}
				offset += field.Size()
			}
		} else {
			if _, isPtrArg := arg.arg.(*prog.PtrType); !isPtrArg && arg.arg.Name() != "ptr" {
				_, tr := te.GetData(offset, arg.arg.Size())
				if (a.argRanges[arg][0] > tr) {
					if flag == TrainFlag {
						a.argRanges[arg][0] = tr
					}
					msgs = append(msgs, fmt.Sprintf("%v:l %x", arg.name, tr))
				}
				if (a.argRanges[arg][1] < tr) {
					if flag == TrainFlag {
						a.argRanges[arg][1] = tr
					}
					msgs = append(msgs, fmt.Sprintf("%v:u %x", arg.name, tr))
				}
			}
			offset += arg.size
		}
	}
	for _, vlr := range te.syscall.vlrMaps {
		_, size := te.GetData(48+vlr.lenOffset, 8)
		_, start := te.GetData(56, 8) // Special case for binder
		offset += start
		for {
			_, tr := te.GetData(offset, 4)
			var matchedRecord *VlrRecord
			if offset < size+vlr.offset+48 {
				for i, record := range vlr.records {
					if tr == record.header {
						matchedRecord = vlr.records[i]
						break
					}
				}
			}
			offset += 4
			if matchedRecord != nil {
				structArg, _ := matchedRecord.arg.(*prog.StructType)
				for i, field := range structArg.Fields {
					if i == 0 {
						continue
					}
					if _, isPtrArg := field.Type.(*prog.PtrType); !isPtrArg && field.Name != "ptr" && field.Name != "cookie" && field.Name != "ref" {
						_, tr = te.GetData(offset, field.Size())
						if (a.vlrRanges[vlr][matchedRecord][2*i+0] > tr) {
							if flag == TrainFlag {
								a.vlrRanges[vlr][matchedRecord][2*i+0] = tr
							}
							msgs = append(msgs, fmt.Sprintf("%v_%v:l [%v]:%x", matchedRecord.name, field.Name, offset, tr))
						}
						if (a.vlrRanges[vlr][matchedRecord][2*i+1] < tr) {
							if flag == TrainFlag {
								a.vlrRanges[vlr][matchedRecord][2*i+1] = tr
							}
							msgs = append(msgs, fmt.Sprintf("%v_%v:u [%v]:%x", matchedRecord.name, field.Name, offset, tr))
						}
					}
					offset += field.Size()
				}
				continue;
			} else {
				break;
			}
		}
	}
	updatedRangesLen := len(msgs)
	updatedRangesMsg := ""
	for i, msg := range msgs {
		updatedRangesMsg += msg
		if i != updatedRangesLen-1 {
			updatedRangesMsg += ", "
		}
	}
	return updatedRangesMsg, updatedRangesLen, 0
}

func (a *ValueRangeAnalysis) PostProcess(opt int) {
}

func (a *ValueRangeAnalysis) PrintResult(v Verbose) {
	for syscall, regRange := range a.regRanges {
		fmt.Printf("\n%v\n", syscall.name)
		for i := 0; i < 6; i++ {
			fmt.Printf("reg[%v] %v\n", i, regRange[i*2:i*2+2])
		}
		for _, arg := range syscall.argMaps {
			fmt.Printf("%v %v\n", arg.name, a.argRanges[arg])
		}
		for _, vlr := range syscall.vlrMaps {
			fmt.Printf("\n%v %v\n", vlr.name, len(vlr.records))
			for _, record := range vlr.records {
				fmt.Printf("%v %v\n", record.name, a.vlrRanges[vlr][record])
			}
		}
	}
}

func (a *ValueRangeAnalysis) GetArgConstraint(syscall *Syscall, arg prog.Type, argMap *ArgMap, depth int) ArgConstraint {
	return nil
}
