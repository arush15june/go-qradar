package qradar

import (
	"context"
	"fmt"
	"net/http"
)

// SearchResultsWindow is a default window for scrolling results of the query.
var SearchResultsWindow = 50

// ScrollPollSeconds is how often ScrollByQuery polls the search status.
var ScrollPollSeconds = 2

// SearchResultsScroller represents a scroller for the results of the query.
//
// Call Err after Next returns false: a failed page read also ends the
// iteration. Call Close when done to delete the search from QRadar.
type SearchResultsScroller struct {
	count             int
	client            *Client
	searchID          string
	startIdx, currIdx int
	window            int
	events            []Event
	err               error
	closed            bool
}

// NewSearchResultsScroller initializes struct to scroll the records.
func (a *ArielService) NewSearchResultsScroller(ctx context.Context, searchID string) (*SearchResultsScroller, error) {
	_, num, err := a.SearchStatus(ctx, searchID)
	if err != nil {
		return nil, err
	}

	srs := &SearchResultsScroller{
		count:    num,
		window:   SearchResultsWindow,
		client:   a.client,
		searchID: searchID,
	}

	err = srs.getEvents(ctx)
	if err != nil {
		return nil, err
	}

	return srs, nil
}

// Next returns true if an event is still available to be consumed by the
// Result() method. It returns false at the end of the results and when a page
// read fails; Err tells the two apart.
func (s *SearchResultsScroller) Next(ctx context.Context) bool {
	if s.err != nil {
		return false
	}

	lastChunkOfData := len(s.events) < s.window+1 // because qradar usually returns s.window+1 events
	lastEventIsRead := s.currIdx-s.startIdx == len(s.events)
	if lastChunkOfData && lastEventIsRead {
		return false
	}

	endOfChunk := s.currIdx-s.startIdx == len(s.events)
	if endOfChunk {
		s.startIdx += s.window
		err := s.getEvents(ctx)
		if err != nil {
			s.err = fmt.Errorf("ariel search %s: read results from item %d: %w", s.searchID, s.startIdx, err)
			return false
		}
		// Pages overlap by one item, so the new page can hold nothing
		// unread when the previous page ended exactly at the last row.
		if s.currIdx-s.startIdx >= len(s.events) {
			return false
		}
	}

	return true
}

// Err returns the error that ended the iteration, or nil when every result
// was read.
func (s *SearchResultsScroller) Err() error {
	return s.err
}

// SearchID returns the id of the Ariel search the scroller reads.
func (s *SearchResultsScroller) SearchID() string {
	return s.searchID
}

// Close deletes the search and its saved results from QRadar. It sends the
// delete with its own bounded context, so it also works after the caller's
// context has ended. A search that is already gone is not an error. Calling
// Close more than once does nothing after the first call.
func (s *SearchResultsScroller) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	return s.client.Ariel.deleteSearchDetached(s.searchID)
}

func (s *SearchResultsScroller) getEvents(ctx context.Context) error {
	req, err := s.client.NewRequest(http.MethodGet, fmt.Sprintf("%s/%s/results", arielSearchAPIPrefix, s.searchID), nil)
	if err != nil {
		return err
	}

	req.Header.Add("Range", fmt.Sprintf("items=%d-%d", s.startIdx, s.startIdx+s.window))

	var r SearchResult
	_, err = s.client.Do(ctx, req, &r)
	if err != nil {
		return err
	}

	s.events = r.Events

	return nil
}

// Result returns the event iterated by the Next.
func (s *SearchResultsScroller) Result() Event {
	event := s.events[s.currIdx-s.startIdx]
	s.currIdx++
	return event

}

// Length returns the overall events count.
func (s *SearchResultsScroller) Length() int {
	return s.count
}

// ScrollByQuery events in the QRadar API.
// Recommended way to retrieve large amount of events.
//
// The caller owns the returned scroller and should Close it to delete the
// search from QRadar. If any step fails after the search was created,
// ScrollByQuery deletes the search itself before it returns the error.
func (a *ArielService) ScrollByQuery(ctx context.Context, sqlQuery string) (*SearchResultsScroller, *SearchMetadata, error) {
	s, err := a.SearchByQuery(ctx, sqlQuery)
	if err != nil {
		return nil, nil, err
	}
	if s.SearchID == nil {
		return nil, nil, fmt.Errorf("ariel search: response has no search_id")
	}
	searchID := *s.SearchID

	fail := func(err error) (*SearchResultsScroller, *SearchMetadata, error) {
		_ = a.deleteSearchDetached(searchID)
		return nil, nil, err
	}

	_, err = a.WaitForSearchID(ctx, searchID, StatusCompleted, ScrollPollSeconds)
	if err != nil {
		return fail(err)
	}

	meta, err := a.SearchMetadata(ctx, searchID)
	if err != nil {
		return fail(err)
	}

	srs, err := a.NewSearchResultsScroller(ctx, searchID)
	if err != nil {
		return fail(err)
	}

	return srs, meta, nil
}
