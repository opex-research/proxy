package utils

import (
	"encoding/csv"
	"fmt"
	"os"
	"sync"
	"time"
)

type Measurements struct {
	sessionID string // Added sessionID field in the structure
	data      []*Measurement
	mu        sync.Mutex
}

type Measurement struct {
	ID        string
	SessionID string
	StartTime time.Time
	EndTime   time.Time
	Duration  time.Duration
}

func (m *Measurement) StartTimeString() string {
	return fmt.Sprintf("%d", m.StartTime.Unix())
}

func (m *Measurement) EndTimeString() string {
	return fmt.Sprintf("%d", m.EndTime.Unix())
}

func (m *Measurement) DurationString() string {
	return fmt.Sprintf("%d", m.Duration.Milliseconds())
}

func NewMeasurements(sessionID string) *Measurements { // Modified to accept sessionID
	return &Measurements{
		sessionID: sessionID,
	}
}

func (m *Measurements) Start(id string) { // Removed sessionID parameter as it's part of the structure
	m.mu.Lock()
	defer m.mu.Unlock()

	measure := &Measurement{
		ID:        id,
		SessionID: m.sessionID,
		StartTime: time.Now(),
	}
	m.data = append(m.data, measure)
}

func (m *Measurements) End(id string) { // Removed sessionID parameter as it's part of the structure
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, measure := range m.data {
		if measure.ID == id && measure.SessionID == m.sessionID && measure.Duration == 0 {
			measure.EndTime = time.Now()
			measure.Duration = measure.EndTime.Sub(measure.StartTime)
			break
		}
	}
}

func (m *Measurements) DumpToCSV(filename string) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	fileStat, err := file.Stat()
	if err != nil {
		return err
	}

	if fileStat.Size() == 0 {
		err = writer.Write([]string{"ID", "SessionID", "StartTime", "EndTime", "Duration"})
		if err != nil {
			return err
		}
	}

	for _, measure := range m.data {
		err := writer.Write([]string{measure.ID, measure.SessionID, measure.StartTimeString(), measure.EndTimeString(), measure.DurationString()})
		if err != nil {
			return err
		}
	}

	return nil
}

func CheckAndCreateDir(dirName string) error {
	if _, err := os.Stat(dirName); os.IsNotExist(err) {
		return os.MkdirAll(dirName, 0755)
	}
	return nil
}
