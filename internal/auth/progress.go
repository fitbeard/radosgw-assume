package auth

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// ProgressInterval is how often to show progress indication.
const ProgressInterval = 5 * time.Second

// ProgressIndicator manages progress indication during authentication.
type ProgressIndicator struct {
	output     io.Writer
	ticks      <-chan time.Time
	stopTicker func()
	done       chan struct{}
	stopped    chan struct{}
	stopOnce   sync.Once
}

// NewProgressIndicator creates and starts a new progress indicator.
func NewProgressIndicator() *ProgressIndicator {
	return newProgressIndicatorWithOutput(os.Stderr)
}

func newProgressIndicatorWithOutput(output io.Writer) *ProgressIndicator {
	ticker := time.NewTicker(ProgressInterval)
	return newProgressIndicator(output, ticker.C, ticker.Stop)
}

func newProgressIndicator(output io.Writer, ticks <-chan time.Time, stopTicker func()) *ProgressIndicator {
	progress := &ProgressIndicator{
		output:     output,
		ticks:      ticks,
		stopTicker: stopTicker,
		done:       make(chan struct{}),
		stopped:    make(chan struct{}),
	}
	go progress.run()
	return progress
}

func (p *ProgressIndicator) run() {
	defer close(p.stopped)
	for {
		select {
		case <-p.ticks:
			_, _ = fmt.Fprint(p.output, "#")
		case <-p.done:
			return
		}
	}
}

// Stop stops the progress indicator and prints a newline.
func (p *ProgressIndicator) Stop() {
	p.stop(true)
}

// StopQuiet stops the progress indicator without printing a newline.
func (p *ProgressIndicator) StopQuiet() {
	p.stop(false)
}

func (p *ProgressIndicator) stop(printNewline bool) {
	p.stopOnce.Do(func() {
		p.stopTicker()
		close(p.done)
		<-p.stopped
		if printNewline {
			_, _ = fmt.Fprintln(p.output)
		}
	})
}
