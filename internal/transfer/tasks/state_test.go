package tasks

import "testing"

func TestTransitionsLegal(t *testing.T) {
	happy := []Status{StatusQueued, StatusDownloading, StatusDownloaded, StatusUploading, StatusRegistering, StatusReady}
	for i := 0; i+1 < len(happy); i++ {
		if !happy[i].Can(happy[i+1]) {
			t.Errorf("happy path %s -> %s should be legal", happy[i], happy[i+1])
		}
	}
	if !StatusDownloading.Can(StatusFailed) || !StatusFailed.Can(StatusDownloading) || !StatusFailed.Can(StatusDead) {
		t.Error("failure edges missing")
	}
}

func TestTransitionsIllegal(t *testing.T) {
	illegal := []struct{ from, to Status }{
		{StatusQueued, StatusReady},
		{StatusQueued, StatusDownloaded},
		{StatusReady, StatusDownloading},
		{StatusReady, StatusFailed},
		{StatusDead, StatusDownloading},
		{StatusDownloading, StatusRegistering},
		{StatusUploading, StatusReady},
	}
	for _, c := range illegal {
		if c.from.Can(c.to) {
			t.Errorf("%s -> %s should be illegal", c.from, c.to)
		}
	}
}
