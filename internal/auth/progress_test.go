package auth

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestProgressIndicator(t *testing.T) {
	tests := []struct {
		name       string
		stop       func(*ProgressIndicator)
		stopAgain  func(*ProgressIndicator)
		emitTick   bool
		wantOutput string
	}{
		{
			name:       "normal stop",
			stop:       (*ProgressIndicator).Stop,
			stopAgain:  (*ProgressIndicator).StopQuiet,
			emitTick:   true,
			wantOutput: "#\n",
		},
		{
			name:       "quiet stop",
			stop:       (*ProgressIndicator).StopQuiet,
			stopAgain:  (*ProgressIndicator).Stop,
			wantOutput: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ticks := make(chan time.Time, 1)
			output := newProgressTestWriter()
			var tickerStops atomic.Int32
			progress := newProgressIndicator(output, ticks, func() { tickerStops.Add(1) })

			if test.emitTick {
				ticks <- time.Now()
				select {
				case write := <-output.writes:
					if write != "#" {
						t.Errorf("progress write = %q, want #", write)
					}
				case <-time.After(time.Second):
					t.Fatal("progress indicator did not render a tick")
				}
			}

			test.stop(progress)
			test.stop(progress)
			test.stopAgain(progress)

			if got := output.String(); got != test.wantOutput {
				t.Errorf("progress output = %q, want %q", got, test.wantOutput)
			}
			if got := tickerStops.Load(); got != 1 {
				t.Errorf("ticker stops = %d, want 1", got)
			}
		})
	}
}

func TestProgressIndicatorConcurrentStops(t *testing.T) {
	output := newProgressTestWriter()
	var tickerStops atomic.Int32
	progress := newProgressIndicator(
		output,
		make(chan time.Time),
		func() { tickerStops.Add(1) },
	)

	const callers = 20
	start := make(chan struct{})
	var waitGroup sync.WaitGroup
	for caller := 0; caller < callers; caller++ {
		waitGroup.Add(1)
		go func(quiet bool) {
			defer waitGroup.Done()
			<-start
			if quiet {
				progress.StopQuiet()
				return
			}
			progress.Stop()
		}(caller%2 == 0)
	}
	close(start)

	done := make(chan struct{})
	go func() {
		waitGroup.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("concurrent progress stops blocked")
	}

	if got := tickerStops.Load(); got != 1 {
		t.Errorf("ticker stops = %d, want 1", got)
	}
	if got := output.String(); got != "" && got != "\n" {
		t.Errorf("progress output = %q, want empty or one newline", got)
	}
}

func TestNewProgressIndicatorStops(t *testing.T) {
	progress := NewProgressIndicator()
	progress.StopQuiet()
	progress.StopQuiet()
}

type progressTestWriter struct {
	mutex  sync.Mutex
	output strings.Builder
	writes chan string
}

func newProgressTestWriter() *progressTestWriter {
	return &progressTestWriter{writes: make(chan string, 32)}
}

func (writer *progressTestWriter) Write(value []byte) (int, error) {
	writer.mutex.Lock()
	defer writer.mutex.Unlock()
	_, _ = writer.output.Write(value)
	writer.writes <- string(value)
	return len(value), nil
}

func (writer *progressTestWriter) String() string {
	writer.mutex.Lock()
	defer writer.mutex.Unlock()
	return writer.output.String()
}
