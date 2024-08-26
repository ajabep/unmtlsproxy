package tests

import "sync"

type SyncedUint struct {
	m sync.Mutex
	v uint
}

func NewSyncedUintFrom(val uint) *SyncedUint {
	s := SyncedUint{
		m: sync.Mutex{},
		v: val,
	}
	return &s
}

func NewSyncedUint() *SyncedUint {
	return NewSyncedUintFrom(0)
}

func (s *SyncedUint) GetInc() uint {
	s.m.Lock()
	defer s.m.Unlock()
	oldVal := s.v
	s.v += 1
	return oldVal
}
