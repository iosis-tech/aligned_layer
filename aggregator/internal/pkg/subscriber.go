package pkg

import (
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"time"
)

const (
	MaxRetries    = 20
	RetryInterval = 10 * time.Second
)

func (agg *Aggregator) SubscribeToNewTasks() error {
	for retries := 0; retries < MaxRetries; retries++ {
		err := agg.tryCreateTaskSubscriber()
		if err == nil {
			_ = agg.subscribeToNewTasks() // This will block until an error occurs
		}

		message := fmt.Sprintf("Failed to subscribe to new tasks. Retrying in %v", RetryInterval)
		agg.AggregatorConfig.BaseConfig.Logger.Info(message)
		time.Sleep(RetryInterval)
	}

	return errors.New("failed to subscribe to new tasks after max retries")
}

func (agg *Aggregator) subscribeToNewTasks() error {
	for {
		select {
		case err := <-agg.taskSubscriber.Err():
			agg.AggregatorConfig.BaseConfig.Logger.Error("Error in subscription", "err", err)
			return err
		case task := <-agg.NewTaskCreatedChan:
			agg.AddNewTask(task.TaskIndex, task.Task)
		}
	}
}

func (agg *Aggregator) tryCreateTaskSubscriber() error {
	var err error

	agg.AggregatorConfig.BaseConfig.Logger.Info("Subscribing to Ethereum serviceManager task events")
	agg.taskSubscriber, err = agg.avsSubscriber.AvsContractBindings.ServiceManager.WatchNewTaskCreated(&bind.WatchOpts{},
		agg.NewTaskCreatedChan, nil)

	if err != nil {
		agg.AggregatorConfig.BaseConfig.Logger.Info("Failed to create task subscriber", "err", err)
	}
	return err
}
