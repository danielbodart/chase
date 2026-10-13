package ssh

import (
	"github.com/danielbodart/frisket/policy"
	"github.com/danielbodart/quoin/execrule"
)

// decide is frisket's answer to command under the route, by the matcher
// frisket itself decides with (quoin's execrule, which frisket imports), so
// that what the catalogue answers is tested here as commands rather than as
// rules, in-process and without frisket on PATH. A route frisket would not load answers with why, which no test
// wants.
func decide(r policy.SSHRoute, command string) string {
	rules, err := execrule.Compile(r.Spec)
	if err != nil {
		return "unloadable: " + err.Error()
	}
	return rules.Decide(command).Outcome.String()
}

// readable is whether any rule of the route could decide command.
func readable(r policy.SSHRoute, command string) bool {
	rules, err := execrule.Compile(r.Spec)
	return err == nil && rules.Readable(command)
}

// outcome is what a rule answers, in the words decide says it in.
func outcome(e policy.ExecRule) string { return answerOf(e) }
