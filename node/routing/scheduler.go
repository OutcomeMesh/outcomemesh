package routing

import (
	"context"
	"time"
)

const MaxSchedulerInterval = time.Hour

type SchedulerConfig struct {
	Interval     time.Duration
	AttemptLimit int
	Preflight    func() error
}

type Observer func([]Result) error

// Scheduler runs non-overlapping bounded routing passes. Per-peer single-flight
// and exponential backoff remain enforced by Router's peer manager; a slow
// connector delays the next tick instead of accumulating goroutines.
type Scheduler struct {
	router    *Router
	config    SchedulerConfig
	connector Connector
	observer  Observer
}

func NewScheduler(router *Router, config SchedulerConfig, connector Connector, observer Observer) (*Scheduler, error) {
	if router == nil || connector == nil || config.Interval <= 0 || config.Interval > MaxSchedulerInterval ||
		config.AttemptLimit <= 0 || config.AttemptLimit > discoveryAttemptLimit {
		return nil, ErrConfiguration
	}
	return &Scheduler{router: router, config: config, connector: connector, observer: observer}, nil
}

func (scheduler *Scheduler) Run(ctx context.Context) error {
	if scheduler == nil || ctx == nil {
		return ErrConfiguration
	}
	for {
		if ctx.Err() != nil {
			return nil
		}
		if scheduler.config.Preflight != nil {
			if err := scheduler.config.Preflight(); err != nil {
				return err
			}
		}
		results := scheduler.router.RunOnce(ctx, scheduler.config.AttemptLimit, scheduler.connector)
		if scheduler.observer != nil {
			if err := scheduler.observer(append([]Result(nil), results...)); err != nil {
				return err
			}
		}
		timer := time.NewTimer(scheduler.config.Interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case <-timer.C:
		}
	}
}
