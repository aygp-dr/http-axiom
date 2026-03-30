package predicate

import "net/http"

// StateGroup returns the stateful interaction predicate group.
func StateGroup() Group {
	return Group{
		Name: GroupState,
		Predicates: []NamedPred{
			{Name: "workflow-skip", Fn: checkWorkflowSkip, Type: TypeUniversal}, // stub: will become TypeSequential+MultiFn
			{Name: "toctou", Fn: checkTOCTOU, Type: TypeUniversal},              // stub: will become TypeSequential+MultiFn
			{Name: "replay", Fn: checkReplay, Type: TypeUniversal},              // stub: will become TypeSequential+MultiFn
		},
	}
}

func checkWorkflowSkip(_ *http.Response) Result {
	return Result{GroupState, "workflow-skip", "skip", "requires stateful multi-step test"}
}

func checkTOCTOU(_ *http.Response) Result {
	return Result{GroupState, "toctou", "skip", "requires concurrent test"}
}

func checkReplay(_ *http.Response) Result {
	return Result{GroupState, "replay", "skip", "requires replay test"}
}
