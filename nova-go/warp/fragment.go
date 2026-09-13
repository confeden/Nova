package warp

import (
	"net"
	"sync"
	"time"
)

// fragmentedConn cuts the first fragmentBytes written bytes (the start of the TLS ClientHello) into
// small TCP writes, so a middlebox that reads the SNI from one segment does not see it whole. It is
// register.go's fragmentedConn with a mutex added; the cutting rules are unchanged:
//   - splitPlan chunks go first, in order, a non-positive entry is skipped;
//   - then fragmentSize chunks up to the limit (no fragmentSize: the rest of the limit in one write);
//   - then the remainder of the same Write call in one write;
//   - delay sleeps between chunks inside the limit, never after the last one.
//
// Once fragmentBytes is used up every Write passes straight through.
type fragmentedConn struct {
	net.Conn
	mu            sync.Mutex
	splitPlan     []int
	fragmentSize  int
	fragmentBytes int
	delay         time.Duration
}

func newFragmentedConn(conn net.Conn, p registrationProfile) net.Conn {
	if len(p.splitPlan) == 0 && (p.fragmentSize <= 0 || p.fragmentBytes <= 0) {
		return conn
	}
	return &fragmentedConn{
		Conn:          conn,
		splitPlan:     append([]int(nil), p.splitPlan...),
		fragmentSize:  p.fragmentSize,
		fragmentBytes: p.fragmentBytes,
		delay:         p.fragmentDelay,
	}
}

func (c *fragmentedConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.fragmentBytes <= 0 || len(p) == 0 {
		return c.Conn.Write(p)
	}

	total := 0
	limit := min(len(p), c.fragmentBytes)

	// consume books what was written against the budget, also on a failed write.
	consume := func() {
		c.fragmentBytes = max(c.fragmentBytes-total, 0)
	}

	for len(c.splitPlan) > 0 && total < limit {
		next := c.splitPlan[0]
		c.splitPlan = c.splitPlan[1:]
		if next <= 0 {
			continue
		}
		end := min(total+next, limit)
		n, err := c.Conn.Write(p[total:end])
		total += n
		if err != nil {
			consume()
			return total, err
		}
		if total < limit && c.delay > 0 {
			time.Sleep(c.delay)
		}
	}

	if c.fragmentSize <= 0 {
		c.fragmentSize = limit
	}
	for total < limit {
		end := min(total+c.fragmentSize, limit)
		n, err := c.Conn.Write(p[total:end])
		total += n
		if err != nil {
			consume()
			return total, err
		}
		if total < limit && c.delay > 0 {
			time.Sleep(c.delay)
		}
	}
	consume()

	if total == len(p) {
		return total, nil
	}
	n, err := c.Conn.Write(p[total:])
	return total + n, err
}
