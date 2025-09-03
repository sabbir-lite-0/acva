package utils

import (
	"fmt"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
)

type ProgressTracker struct {
	bars   map[string]*progressbar.ProgressBar
	mu     sync.Mutex
	active bool
}

func NewProgressTracker() *ProgressTracker {
	return &ProgressTracker{
		bars: make(map[string]*progressbar.ProgressBar),
	}
}

func (p *ProgressTracker) AddTask(name string, total int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.active {
		return
	}

	bar := progressbar.NewOptions(total,
		progressbar.OptionSetDescription(name),
		progressbar.OptionSetWriter(color.Output),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(30),
		progressbar.OptionThrottle(65*time.Millisecond),
		progressbar.OptionShowElapsedTimeOnFinish(),
		progressbar.OptionOnCompletion(func() {
			fmt.Printf("\n")
		}),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionFullWidth(),
		progressbar.OptionSetRenderBlankState(true),
	)

	p.bars[name] = bar
}

func (p *ProgressTracker) IncrementTask(name string, amount int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if bar, exists := p.bars[name]; exists {
		bar.Add(amount)
	}
}

func (p *ProgressTracker) CompleteTask(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if bar, exists := p.bars[name]; exists {
		bar.Finish()
		delete(p.bars, name)
	}
}

func (p *ProgressTracker) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.active = false
	for name, bar := range p.bars {
		bar.Finish()
		delete(p.bars, name)
	}
}

func (p *ProgressTracker) Start() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.active = true
}
