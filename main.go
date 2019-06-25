package main

import (
	"os"

	gitleaks "github.com/gilclark/gitleaks/src"
	log "github.com/sirupsen/logrus"
)

func main() {
	report, err := gitleaks.Run(gitleaks.ParseOpts())
	if err != nil {
		log.Error(err)
		os.Exit(gitleaks.ErrExit)
	}

	if len(report.Leaks) != 0 {
		log.Warnf("%d leaks detected. %d commits inspected in %s", len(report.Leaks), report.Commits, report.Duration)
		os.Exit(gitleaks.LeakExit)
	} else {
		log.Infof("%d leaks detected. %d commits inspected in %s", len(report.Leaks), report.Commits, report.Duration)
	}
}
