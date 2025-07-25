package sifter

import (
	"fmt"
	"strings"

	"github.com/google/syzkaller/prog"
)


type FlagBitField struct {
	width  int
	offset int
	mask   uint64
	values map[uint64]int
}

type FlagSet struct {
	values map[uint64]map[*Trace]int
	idx    int
	offset uint64
	size   uint64
	tag    bool
	bf     bool
	bitFields []FlagBitField
}

func NewBitField(w int, off int) FlagBitField {
	var bf FlagBitField
	bf.width = w
	bf.offset = off
	bf.mask = (1 << w)-1
	fmt.Printf("%v %v mask %x\n", w, off, bf.mask)
	bf.values = make(map[uint64]int)
	return bf
}

func (flags *FlagSet) UpdateBitFields(v uint64, te *TraceEvent, f AnalysisFlag, opt int, tag bool) (bool, bool) {
	update := false
	updateOL := false
	if f == TrainFlag && opt == 0 {
		for _, bf := range flags.bitFields {
			if _, ok := bf.values[(v >> bf.offset) & bf.mask]; !ok {
				update = true
			}
			bf.values[(v >> bf.offset) & bf.mask] += 1
			//fmt.Printf("%v\n", flags)
		}
	} else if f == TestFlag {
		for _, bf := range flags.bitFields {
			if _, ok := bf.values[(v >> bf.offset) & bf.mask]; !ok {
				update = true
			}
			//bf.values[(v & bf.mask) >> bf.offset] += 1
		}
	}
	return update, updateOL
}

func (flags *FlagSet) UpdateValues(v uint64, te *TraceEvent, f AnalysisFlag, opt int, tag bool) (bool, bool) {
	_, ok := flags.values[v]
	if !ok {
		flags.values[v] = make(map[*Trace]int)
	}

	update := false
	updateOL := false
	if f == TrainFlag {
		if opt == 0 {
			flags.values[v][te.trace] += 1
			update = !ok
		} else if opt == 1 {
			if _, ok := flags.values[v][nil]; ok {
				updateOL = true
			} else if _, ok := flags.values[v]; !ok {
				update = true
			}
		}
	} else if f == TestFlag {
		if _, ok := flags.values[v][nil]; ok {
			flags.values[v][nil] += 1
			if flags.values[v][nil] > 10 {
				fmt.Printf("Warning: might have a false positive\n")
				update = true
			} else {
				updateOL = true
			}
		} else if _, ok := flags.values[v]; !ok {
			update = true
		}
	}

	if (f == TestFlag) || (f == TrainFlag && !updateOL) {
		if tag && flags.tag {
			te.tags = append(te.tags, int(v))
		}
	} else {
		te.flag = te.flag | TraceEventFlagBadData
	}
	return update, updateOL
}

func (flags *FlagSet) Update(v uint64, te *TraceEvent, f AnalysisFlag, opt int, tag bool) (bool, bool) {
	if flags.bf {
		return flags.UpdateBitFields(v, te, f, opt, tag)
	} else {
		return flags.UpdateValues(v, te, f, opt, tag)
	}
}

func (flags *FlagSet) RemoveOutlier(traceNum int) bool {
	sum := 0
	trace := 0
	for _, traceCounts := range flags.values {
		trace += 1
		for _, count := range traceCounts {
			sum += count
		}
	}
	traceThreshold := 0.000001
	outliers := make([]string, 0)
	for v, traceCounts := range flags.values {
		if float64(len(traceCounts)) / float64(traceNum) < traceThreshold && trace == 1 {
			outliers = append(outliers, fmt.Sprintf("%v(%v/%v)\n", v, sum, len(traceCounts)))
			flags.values[v][nil] = 0
		}
	}
	if len(outliers) > 0 {
		fmt.Printf("remove:\n")
		for _, outlier := range outliers {
			fmt.Printf("%x", outlier)
		}
	}
	return len(outliers) != 0
}

func newFlagSet(idx int, offset uint64, size uint64, tag bool, bfs [][]int) *FlagSet {
	newFlags := new(FlagSet)
	newFlags.values = make(map[uint64]map[*Trace]int)
	newFlags.idx = idx
	newFlags.offset = offset
	newFlags.size = size
	newFlags.tag = tag
	if bfs != nil {
		newFlags.bf = true
		for _, bf := range bfs {
			newFlags.bitFields = append(newFlags.bitFields, NewBitField(bf[0], bf[1]))
		}
	}
	return newFlags
}

func (flags *FlagSet) String() string {
	s := ""
	if !flags.bf {
	for flag, traceCounts := range flags.values {
		counts := 0
		for _, count := range traceCounts {
			counts += count
		}
		s += fmt.Sprintf("0x%x(%d/%d) ", flag, counts, len(traceCounts))
	}
	} else {
		for _, bf := range flags.bitFields {
			s += fmt.Sprintf("%v,%v: ", bf.width, bf.offset)
			for v, count := range bf.values {
				s += fmt.Sprintf("0x%x(%v) ", v, count)
			}
		}
	}
	return s
}

type FlagAnalysis struct {
	argFlags map[*ArgMap]map[prog.Type]*FlagSet
	regFlags map[*Syscall]map[prog.Type]*FlagSet
	vlrFlags map[*VlrMap]map[*VlrRecord]map[prog.Type]*FlagSet
	tracedSyscalls map[*Syscall]bool
	traces map[*Trace]bool
	noTagFlags map[string]bool
	bitFields map[string][][]int
}

func (a *FlagAnalysis) String() string {
	return "flag analysis"
}

func (a *FlagAnalysis) DisableTagging(arg string) {
	if a.noTagFlags == nil {
		a.noTagFlags = make(map[string]bool)
	}
	a.noTagFlags[arg] = false
}

func (a *FlagAnalysis) AddBitFields(arg string, bf [][]int) {
	if a.bitFields == nil {
		a.bitFields = make(map[string][][]int)
	}
	a.bitFields[arg] = bf
}

// Helper to get the field name from a prog.Type if it's a prog.Field
func getFieldName(t prog.Type) string {
	return t.Name()
}

func (a *FlagAnalysis) isFlagsTypeInner(arg prog.Type, syscall *Syscall) bool {
	if syscall.def.CallName == "ioctl" && arg == syscall.def.Args[1].Type {
		return true
	}
	if _, isFlagsArg := arg.(*prog.FlagsType); isFlagsArg {
		return true
	}
	flagStrings := []string{"flag", "flags", "type"}
	for _, flagString := range flagStrings {
		if strings.Contains(getFieldName(arg), flagString) {
			return true
		}
	}
	return false
}

func (a *FlagAnalysis) isFlagsType(arg prog.Field, syscall *Syscall) bool {
	if arg.Direction == prog.DirOut {
		return false
	}

	return a.isFlagsTypeInner(arg.Type, syscall)
}


func (a *FlagAnalysis) Init(TracedSyscalls *map[string][]*Syscall) {
	a.argFlags = make(map[*ArgMap]map[prog.Type]*FlagSet)
	a.regFlags = make(map[*Syscall]map[prog.Type]*FlagSet)
	a.vlrFlags = make(map[*VlrMap]map[*VlrRecord]map[prog.Type]*FlagSet)
	a.tracedSyscalls = make(map[*Syscall]bool)
	a.traces = make(map[*Trace]bool)

	for _, syscalls := range *TracedSyscalls {
		for _, syscall := range syscalls {
			var offset uint64
			idx := 0
			a.regFlags[syscall] = make(map[prog.Type]*FlagSet)
			for argi, arg := range syscall.def.Args {
				if a.isFlagsType(arg, syscall) {
					_, noTag := a.noTagFlags[fmt.Sprintf("%v_reg[%v]", syscall.name, argi)]
					bf, _ := a.bitFields[fmt.Sprintf("%v_reg[%v]", syscall.name, argi)]
					a.regFlags[syscall][arg.Type] = newFlagSet(idx, offset, 8, !noTag, bf)
					idx += 1
				}
				offset += 8
			}
			offset = 48
			for _, argMap := range syscall.argMaps {
				a.argFlags[argMap] = make(map[prog.Type]*FlagSet)
				if structArg, ok := argMap.arg.(*prog.StructType); ok {
					for _, field := range structArg.Fields {
						if a.isFlagsType(field, syscall) {
							_, noTag := a.noTagFlags[fmt.Sprintf("%v_%v", argMap.name, field.Name)]
							bf, _ := a.bitFields[fmt.Sprintf("%v_%v", argMap.name, field.Name)]
							fmt.Printf("%v_%v_%v %v\n", syscall.name, argMap.name, field.Name, noTag)
							a.argFlags[argMap][field.Type] = newFlagSet(idx, offset, field.Size(), !noTag, bf)
							idx += 1
						}
						offset += field.Size()
					}
				} else {
					if a.isFlagsTypeInner(argMap.arg, syscall) {
						_, noTag := a.noTagFlags[fmt.Sprintf("%v", argMap.name)]
						bf, _ := a.bitFields[fmt.Sprintf("%v", argMap.name)]
						fmt.Printf("%v_%v %v\n", syscall.name, argMap.name, noTag)
						a.argFlags[argMap][argMap.arg] = newFlagSet(idx, offset, argMap.size, !noTag, bf)
						idx += 1
					}
					offset += argMap.size
				}
			}
			for _, vlr := range syscall.vlrMaps {
				a.vlrFlags[vlr] = make(map[*VlrRecord]map[prog.Type]*FlagSet)
				for _, record := range vlr.records {
					a.vlrFlags[vlr][record] = make(map[prog.Type]*FlagSet)
					if structArg, ok := record.arg.(*prog.StructType); ok {
						for _, f := range structArg.Fields {
							if structField, ok := f.Type.(*prog.StructType); ok {
								for _, ff := range structField.Fields {
									if a.isFlagsType(ff, syscall) {
										_, noTag := a.noTagFlags[fmt.Sprintf("%v_%v_%v_%v", syscall.name, vlr.name, f.Name, ff.Name)]
										bf, _ := a.bitFields[fmt.Sprintf("%v_%v_%v_%v", syscall.name, vlr.name, f.Name, ff.Name)]
										a.vlrFlags[vlr][record][ff.Type] = newFlagSet(idx, offset, 0, !noTag, bf)
										idx += 1
									}
								}
							} else {
								if a.isFlagsType(f, syscall) {
									_, noTag := a.noTagFlags[fmt.Sprintf("%v_%v_%v", syscall.name, vlr.name, f.Name)]
									bf, _ := a.bitFields[fmt.Sprintf("%v_%v_%v", syscall.name, vlr.name, f.Name)]
									a.vlrFlags[vlr][record][f.Type] = newFlagSet(idx, offset, 0, !noTag, bf)
									idx += 1
								}
							}
						}
					}
				}
			}
		}
	}
}

func (a *FlagAnalysis) Reset() {
}

func (a *FlagAnalysis) ProcessTraceEvent(te *TraceEvent, flag AnalysisFlag, opt int) (string, int, int) {
	if te.typ != 1 {
		return "", 0, 0
	}

	a.tracedSyscalls[te.syscall] = true
	a.traces[te.trace] = true

	var ol []bool
	msgs := make([]string, 0)
	var offset uint64
	for i, arg := range te.syscall.def.Args {
		if flags, ok := a.regFlags[te.syscall][arg.Type]; ok {
			_, tr := te.GetData(offset, 8)
			update, updateOL := flags.Update(tr, te, flag, opt, true)
			if update || updateOL {
				msgs = append(msgs, fmt.Sprintf("reg[%v] new flag %x", i, tr))
				ol  = append(ol, updateOL)
			}
		}
		offset += 8
	}
	offset = 48
	for _, argMap := range te.syscall.argMaps {
		arrayLen := argMap.length
		arrayLenEnd := arrayLen
		isArray := (arrayLen != 1)
		if isArray {
			_, tr := te.GetData(48+argMap.lenOffset, 4)
			if arrayLen < int(tr) {
				fmt.Printf("number of elements in array %v, %x, exceeds the size of tracing buffer!\n", argMap.name, tr)
			} else {
				arrayLen = int(tr)
			}
			arrayLenEnd = 10
		}
		for i := 0; i < arrayLen; i++ {
			if structArg, ok := argMap.arg.(*prog.StructType); ok {
				for _, field := range structArg.Fields {
					if flags, ok := a.argFlags[argMap][field.Type]; ok {
						_, tr := te.GetData(offset, field.Size())
						update, updateOL := flags.Update(tr, te, flag, opt, !isArray)
						if update || updateOL {
							msgs = append(msgs, fmt.Sprintf("%v_%v new flag %x", argMap.name, field.Name, tr))
							ol  = append(ol, updateOL)
						}
					}
					offset += field.Size()
				}
			} else {
				if flags, ok := a.argFlags[argMap][argMap.arg]; ok {
					_, tr := te.GetData(offset, argMap.arg.Size())
					update, updateOL := flags.Update(tr, te, flag, opt, !isArray)
					if update || updateOL {
						msgs = append(msgs, fmt.Sprintf("%v new flag %x", argMap.name, tr))
						ol  = append(ol, updateOL)
					}
				}
				offset += argMap.arg.Size()
			}
		}
		for i := arrayLen; i < arrayLenEnd; i++ {
			offset += argMap.arg.Size()
		}
	}
	for _, vlrMap := range te.syscall.vlrMaps {
		_, size := te.GetData(48+vlrMap.lenOffset, 8)
		_, start := te.GetData(56, 8) // Special case for binder
		offset += start
		for {
			_, tr := te.GetData(offset, 4)
			var vlrRecord *VlrRecord
			if offset < size+vlrMap.offset+48 {
				for i, record := range vlrMap.records {
					if tr == record.header {
						vlrRecord = vlrMap.records[i]
						break
					}
				}
			}
			offset += 4
			if vlrRecord != nil {
				structArg, _ := vlrRecord.arg.(*prog.StructType)
				for i, f := range structArg.Fields {
					if i == 0 {
						continue
					}
					if structField, ok := f.Type.(*prog.StructType); ok {
						fieldOffset := uint64(0)
						for _, ff := range structField.Fields {
							if flags, ok := a.vlrFlags[vlrMap][vlrRecord][ff.Type]; ok {
								_, tr := te.GetData(offset+fieldOffset, ff.Size())
								update, updateOL := flags.Update(tr, te, flag, opt, false)
								if update || updateOL {
									msgs = append(msgs, fmt.Sprintf("%v_%v_%v new flag %x", vlrRecord.name, f.Name, ff.Name, tr))
									ol  = append(ol, updateOL)
								}
							}
							fieldOffset += ff.Size()
						}
					} else {
						if flags, ok := a.vlrFlags[vlrMap][vlrRecord][f.Type]; ok {
							_, tr := te.GetData(offset, f.Size())
							update, updateOL := flags.Update(tr, te, flag, opt, false)
							if update || updateOL {
								msgs = append(msgs, fmt.Sprintf("%v_%v new flag %x", vlrRecord.name, f.Name, tr))
								ol  = append(ol, updateOL)
							}
						}
					}
					offset += f.Size()
				}
				continue;
			} else {
				break;
			}
		}
	}
	updateMsg := ""
	updateFP := 0
	updateTP := 0
	for i, msg := range msgs {
		updateMsg += msg
		if ol[i] {
			updateMsg += " outlier"
			updateTP += 1
		} else {
			updateFP += 1
		}
		if i != len(msg)-1 {
			updateMsg += ", "
		}
	}
	return updateMsg, updateFP, updateTP
}

func (a *FlagAnalysis) PostProcess(opt int) {
	if opt == 0 {
		a.RemoveOutliers()
	}
}

func (a *FlagAnalysis) RemoveOutliers() {
	fmt.Printf("removing outlier flag:\n")
	traceNum := len(a.traces)
	for syscall, _ := range a.tracedSyscalls {
		fmt.Printf("%v\n", syscall.name)
		for i, arg := range syscall.def.Args {
			if flags, ok := a.regFlags[syscall][arg.Type]; ok {
				fmt.Printf("reg[%v]:\n", i)
				if flags.RemoveOutlier(traceNum) {
					fmt.Printf("%v\n", flags)
				}
			}
		}
		for _, argMap := range syscall.argMaps {
			if structArg, ok := argMap.arg.(*prog.StructType); ok {
				for _, field := range structArg.Fields {
					if flags, ok := a.argFlags[argMap][field.Type]; ok {
						fmt.Printf("%v_%v:\n", argMap.name, field.Name)
						if flags.RemoveOutlier(traceNum) {
							fmt.Printf("%v\n", flags)
						}
					}
				}
			} else {
				if flags, ok := a.argFlags[argMap][argMap.arg]; ok {
					fmt.Printf("%v:\n", argMap.name)
					if flags.RemoveOutlier(traceNum) {
						fmt.Printf("%v\n", flags)
					}
				}
			}
		}
		for _, vlrMap := range syscall.vlrMaps {
			fmt.Printf("\n%v (%v)\n", vlrMap.name, len(vlrMap.records))
			for _, vlrRecord := range vlrMap.records {
				structArg, _ := vlrRecord.arg.(*prog.StructType)
				for _, f := range structArg.Fields {
					if structField, isStructArg := f.Type.(*prog.StructType); isStructArg {
						for _, ff := range structField.Fields {
							if flags, ok := a.vlrFlags[vlrMap][vlrRecord][ff.Type]; ok {
								fmt.Printf("%v_%v_%v:\n", vlrRecord.name, f.Name, ff.Name)
								if flags.RemoveOutlier(traceNum) {
									fmt.Printf("%v\n", flags)
								}
							}
						}
					} else {
						if flags, ok := a.vlrFlags[vlrMap][vlrRecord][f.Type]; ok {
							fmt.Printf("%v_%v:\n", vlrRecord.name, f.Name)
							if flags.RemoveOutlier(traceNum) {
								fmt.Printf("%v\n", flags)
							}
						}
					}
				}
			}
		}
	}
}

func (a *FlagAnalysis) PrintResult(v Verbose) {
	for syscall, _ := range a.tracedSyscalls {
		s := ""
		for i, arg := range syscall.def.Args {
			if flags, ok := a.regFlags[syscall][arg.Type]; ok {
				s += fmt.Sprintf("reg[%v]: %v\n", i, flags)
			}
		}
		for _, argMap := range syscall.argMaps {
			if structArg, ok := argMap.arg.(*prog.StructType); ok {
				for _, field := range structArg.Fields {
					if flags, ok := a.argFlags[argMap][field.Type]; ok {
						 s += fmt.Sprintf("%v_%v: %v\n", argMap.name, field.Name, flags)
					}
				}
			} else {
				if flags, ok := a.argFlags[argMap][argMap.arg]; ok {
					s += fmt.Sprintf("%v: %v\n", argMap.name, flags)
				}
			}
		}
		for _, vlrMap := range syscall.vlrMaps {
			fmt.Printf("\n%v (%v)\n", vlrMap.name, len(vlrMap.records))
			for _, vlrRecord := range vlrMap.records {
				structArg, _ := vlrRecord.arg.(*prog.StructType)
				for _, f := range structArg.Fields {
					if structField, isStructArg := f.Type.(*prog.StructType); isStructArg {
						for _, ff := range structField.Fields {
							if flags, ok := a.vlrFlags[vlrMap][vlrRecord][ff.Type]; ok {
								s += fmt.Sprintf("%v_%v_%v: %v\n", vlrRecord.name, f.Name, ff.Name, flags)
							}
						}
					} else {
						if flags, ok := a.vlrFlags[vlrMap][vlrRecord][f.Type]; ok {
							s += fmt.Sprintf("%v_%v: %v\n", vlrRecord.name, f.Name, flags)
						}
					}
				}
			}
		}
		if len(s) != 0 {
			fmt.Print("--------------------------------------------------------------------------------\n")
			fmt.Printf("%v\n%s", syscall.name, s)
		}
	}
}

func (a *FlagAnalysis) GetArgConstraint(syscall *Syscall, arg prog.Type, argMap *ArgMap, depth int) ArgConstraint {
	if _, ok := a.tracedSyscalls[syscall]; !ok {
		return nil
	}

	if depth == 0 {
		if f, ok := a.regFlags[syscall][arg]; ok {
			if f.tag {
				var constraint *TaggingConstraint
				fmt.Printf("add tagging constraint to %v %v\n", syscall.name, arg.Name)
				constraint = new(TaggingConstraint)
				constraint.idx = f.idx
				return constraint
			} else {
				var constraint *ValuesConstraint
				fmt.Printf("add values constraint to %v %v\n", syscall.name, arg.Name)
				constraint = new(ValuesConstraint)
				for v, _ := range f.values {
					constraint.values = append(constraint.values, v)
				}
				return constraint
			}
		}
	} else {
		if f, ok := a.argFlags[argMap][arg]; ok {
			if f.tag {
				var constraint *TaggingConstraint
				fmt.Printf("add tagging constraint to %v %v %v\n", syscall.name, argMap.name, arg.Name)
				constraint = new(TaggingConstraint)
				constraint.idx = f.idx
				return constraint
			} else {
				var constraint *ValuesConstraint
				fmt.Printf("add values constraint to %v %v %v\n", syscall.name, argMap.name, arg.Name)
				constraint = new(ValuesConstraint)
				for v, _ := range f.values {
					constraint.values = append(constraint.values, v)
				}
				return constraint
			}
		}
	}
	return nil
}

