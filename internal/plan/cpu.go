package plan

import "runtime"

func runtimeNumCPU() int { return runtime.NumCPU() }
