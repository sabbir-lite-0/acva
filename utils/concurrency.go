package utils

import (
	"sync"
	"time"
)

type WorkerPool struct {
	workers    int
	jobQueue   chan func() error
	wg         sync.WaitGroup
	delay      time.Duration
	retries    int
	semaphore  chan struct{}
	errorCount int
	maxErrors  int
}

func NewWorkerPool(workers, retries int, delay time.Duration) *WorkerPool {
	pool := &WorkerPool{
		workers:   workers,
		jobQueue:  make(chan func() error, workers*2),
		delay:     delay,
		retries:   retries,
		semaphore: make(chan struct{}, workers),
		maxErrors: 100, // Maximum allowed errors before aborting
	}
	pool.start()
	return pool
}

func (p *WorkerPool) start() {
	for i := 0; i < p.workers; i++ {
		go p.worker()
	}
}

func (p *WorkerPool) worker() {
	for job := range p.jobQueue {
		p.semaphore <- struct{}{}
		
		var err error
		for attempt := 0; attempt <= p.retries; attempt++ {
			err = job()
			if err == nil {
				break
			}
			
			if attempt < p.retries {
				time.Sleep(time.Duration(attempt+1) * p.delay)
			}
		}
		
		if err != nil {
			p.errorCount++
			if p.errorCount >= p.maxErrors {
				// Too many errors, abort processing
				close(p.jobQueue)
				break
			}
		}
		
		<-p.semaphore
		p.wg.Done()
	}
}

func (p *WorkerPool) Submit(job func() error) {
	p.wg.Add(1)
	p.jobQueue <- job
}

func (p *WorkerPool) Wait() {
	close(p.jobQueue)
	p.wg.Wait()
}

func (p *WorkerPool) ErrorCount() int {
	return p.errorCount
}

func (p *WorkerPool) HasTooManyErrors() bool {
	return p.errorCount >= p.maxErrors
}
