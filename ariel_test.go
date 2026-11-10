package qradar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeAriel is a minimal Ariel API. It records every call.
type fakeAriel struct {
	mu        sync.Mutex
	calls     []string
	statuses  []string // returned by successive status polls; the last repeats
	polls     int
	rows      int
	failPage  int // the results request that starts at this item fails; -1 = never
	deleteRes func(w http.ResponseWriter)
}

func (f *fakeAriel) deletes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == "DELETE /api/ariel/searches/s1" {
			n++
		}
	}
	return n
}

func (f *fakeAriel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	f.mu.Unlock()

	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/ariel/searches":
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"search_id":"s1","status":"WAIT"}`)
	case r.Method == http.MethodGet && r.URL.Path == "/api/ariel/searches/s1":
		f.mu.Lock()
		st := f.statuses[len(f.statuses)-1]
		if f.polls < len(f.statuses) {
			st = f.statuses[f.polls]
		}
		f.polls++
		f.mu.Unlock()
		body := map[string]any{"search_id": "s1", "status": st, "record_count": f.rows}
		if st == "ERROR" {
			body["error_messages"] = []map[string]any{{"message": "query timed out"}}
		}
		_ = json.NewEncoder(w).Encode(body)
	case r.Method == http.MethodGet && r.URL.Path == "/api/ariel/searches/s1/metadata":
		fmt.Fprint(w, `{"columns":[]}`)
	case r.Method == http.MethodGet && r.URL.Path == "/api/ariel/searches/s1/results":
		var from, to int
		_, _ = fmt.Sscanf(r.Header.Get("Range"), "items=%d-%d", &from, &to)
		if f.failPage >= 0 && from == f.failPage {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"message":"boom","code":"1020"}`)
			return
		}
		events := []map[string]any{}
		for i := from; i <= to && i < f.rows; i++ {
			events = append(events, map[string]any{"n": i})
		}
		w.WriteHeader(http.StatusPartialContent)
		_ = json.NewEncoder(w).Encode(map[string]any{"events": events})
	case r.Method == http.MethodDelete && r.URL.Path == "/api/ariel/searches/s1":
		if f.deleteRes != nil {
			f.deleteRes(w)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprint(w, `{"search_id":"s1","status":"COMPLETED"}`)
	default:
		http.NotFound(w, r)
	}
}

func newFake(t *testing.T, f *fakeAriel) *Client {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL+"/", SetSECKey("k"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func withFastPoll(t *testing.T) {
	t.Helper()
	oldPoll, oldWindow := ScrollPollSeconds, SearchResultsWindow
	ScrollPollSeconds = 1
	SearchResultsWindow = 5
	t.Cleanup(func() { ScrollPollSeconds, SearchResultsWindow = oldPoll, oldWindow })
}

func readAll(ctx context.Context, s *SearchResultsScroller) int {
	n := 0
	for s.Next(ctx) {
		s.Result()
		n++
	}
	return n
}

func TestScrollReadsAllAndCloseDeletes(t *testing.T) {
	withFastPoll(t)
	f := &fakeAriel{statuses: []string{"EXECUTE", "COMPLETED"}, rows: 12, failPage: -1}
	c := newFake(t, f)

	s, _, err := c.Ariel.ScrollByQuery(context.Background(), "select 1")
	if err != nil {
		t.Fatal(err)
	}
	if got := readAll(context.Background(), s); got != 12 {
		t.Fatalf("rows = %d, want 12", got)
	}
	if err := s.Err(); err != nil {
		t.Fatalf("Err = %v", err)
	}
	if s.SearchID() != "s1" {
		t.Fatalf("SearchID = %q", s.SearchID())
	}
	if f.deletes() != 0 {
		t.Fatal("search deleted before Close")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if f.deletes() != 1 {
		t.Fatalf("deletes = %d, want 1", f.deletes())
	}
}

func TestScrollRowCountsAroundPageEdges(t *testing.T) {
	withFastPoll(t)
	for _, rows := range []int{0, 1, 5, 6, 7, 10, 11, 12} {
		t.Run(fmt.Sprint(rows), func(t *testing.T) {
			f := &fakeAriel{statuses: []string{"COMPLETED"}, rows: rows, failPage: -1}
			c := newFake(t, f)
			s, _, err := c.Ariel.ScrollByQuery(context.Background(), "select 1")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			seen := map[any]bool{}
			for s.Next(context.Background()) {
				ev := s.Result()
				if seen[ev["n"]] {
					t.Fatalf("row %v read twice", ev["n"])
				}
				seen[ev["n"]] = true
			}
			if len(seen) != rows || s.Err() != nil {
				t.Fatalf("read %d rows (err %v), want %d", len(seen), s.Err(), rows)
			}
		})
	}
}

func TestScrollPageFailureIsReported(t *testing.T) {
	withFastPoll(t)
	f := &fakeAriel{statuses: []string{"COMPLETED"}, rows: 12, failPage: 5}
	c := newFake(t, f)

	s, _, err := c.Ariel.ScrollByQuery(context.Background(), "select 1")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got := readAll(context.Background(), s); got != 6 {
		t.Fatalf("rows = %d, want 6 (items 0-5) before the failed page", got)
	}
	if s.Err() == nil {
		t.Fatal("Err = nil after a failed page read")
	}
}

func TestSearchErrorStatusStopsAndDeletes(t *testing.T) {
	withFastPoll(t)
	f := &fakeAriel{statuses: []string{"EXECUTE", "ERROR"}, failPage: -1}
	c := newFake(t, f)

	_, _, err := c.Ariel.ScrollByQuery(context.Background(), "select 1")
	var sf *SearchFailedError
	if !errors.As(err, &sf) || sf.Status != StatusError {
		t.Fatalf("err = %v, want SearchFailedError(ERROR)", err)
	}
	if !strings.Contains(err.Error(), "query timed out") {
		t.Fatalf("err %q does not carry QRadar's message", err)
	}
	if f.deletes() != 1 {
		t.Fatalf("deletes = %d, want 1", f.deletes())
	}
}

func TestCancelledWaitStillDeletes(t *testing.T) {
	withFastPoll(t)
	f := &fakeAriel{statuses: []string{"EXECUTE"}, failPage: -1}
	c := newFake(t, f)

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	_, _, err := c.Ariel.ScrollByQuery(ctx, "select 1")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if f.deletes() != 1 {
		t.Fatalf("deletes = %d, want 1 (sent with its own context)", f.deletes())
	}
}

func TestDeleteSearchResponses(t *testing.T) {
	cases := []struct {
		name     string
		res      func(w http.ResponseWriter)
		wantErr  bool
		notFound bool
	}{
		{"empty body", func(w http.ResponseWriter) { w.WriteHeader(http.StatusAccepted) }, false, false},
		{"no status field", func(w http.ResponseWriter) { fmt.Fprint(w, `{"search_id":"s1"}`) }, false, false},
		{"not found", func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"message":"search does not exist","code":"1002"}`)
		}, true, true},
		{"not found, plain body", func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "gone")
		}, true, true},
		{"server error", func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"message":"boom"}`)
		}, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeAriel{statuses: []string{"COMPLETED"}, failPage: -1, deleteRes: tc.res}
			c := newFake(t, f)
			_, err := c.Ariel.DeleteSearch(context.Background(), "s1")
			if (err != nil) != tc.wantErr {
				t.Fatalf("DeleteSearch err = %v, wantErr %v", err, tc.wantErr)
			}
			if IsNotFound(err) != tc.notFound {
				t.Fatalf("IsNotFound(%v) = %v, want %v", err, IsNotFound(err), tc.notFound)
			}
			if err != nil && err.Error() == "" {
				t.Fatal("empty error text")
			}
		})
	}
}

func TestCloseIgnoresAlreadyDeleted(t *testing.T) {
	withFastPoll(t)
	f := &fakeAriel{statuses: []string{"COMPLETED"}, rows: 1, failPage: -1, deleteRes: func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"search does not exist","code":"1002"}`)
	}}
	c := newFake(t, f)
	s, _, err := c.Ariel.ScrollByQuery(context.Background(), "select 1")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close on a gone search = %v, want nil", err)
	}
}
