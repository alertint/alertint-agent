// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql/driver"
	"log/slog"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

// holdConnector opens store connections that time each hold: from
// database/sql handing the connection to a store call (ResetSession) to
// getting it back (IsValid). The store has one connection, so one long hold
// is every other store call's wait. The wait totals cannot say who held it;
// this names the holder (issue #99).
type holdConnector struct {
	driver.Connector

	watch *holdWatch
}

// sqliteConn is the driver interfaces the SQLite connection implements and
// database/sql looks for. heldConn embeds it so it hides none of them.
type sqliteConn interface {
	driver.Conn
	driver.ConnBeginTx
	driver.ConnPrepareContext
	driver.ExecerContext
	driver.QueryerContext
	driver.Pinger
	driver.SessionResetter
	driver.Validator
}

func (c holdConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	full, ok := conn.(sqliteConn)
	if !ok {
		return conn, nil // untimed rather than missing an interface
	}
	return &heldConn{sqliteConn: full, watch: c.watch}, nil
}

// heldConn records when and where a hold starts. database/sql calls
// ResetSession and IsValid under the connection's own lock, so these fields
// need none. A new connection's first use has no ResetSession and goes
// untimed.
type heldConn struct {
	sqliteConn

	watch *holdWatch
	since time.Time
	pcs   [32]uintptr
	n     int
}

func (c *heldConn) ResetSession(ctx context.Context) error {
	c.since = time.Now()
	c.n = runtime.Callers(2, c.pcs[:])
	return c.sqliteConn.ResetSession(ctx)
}

func (c *heldConn) IsValid() bool {
	if !c.since.IsZero() {
		c.watch.released(time.Since(c.since), c.pcs[:c.n])
		c.since = time.Time{}
	}
	return c.sqliteConn.IsValid()
}

// holdWatch logs every hold of at least threshold once WatchConnectionWait
// gives it a logger.
type holdWatch struct {
	logger    atomic.Pointer[slog.Logger]
	threshold atomic.Int64
}

func (w *holdWatch) released(held time.Duration, pcs []uintptr) {
	logger := w.logger.Load()
	if logger == nil || held < time.Duration(w.threshold.Load()) {
		return
	}
	logger.Warn("store: connection held", slog.Duration("held", held), slog.String("holder", holderOf(pcs)))
}

// holderOf names the store call that took the connection: up to three frames
// outside database/sql, innermost first, without their package paths.
func holderOf(pcs []uintptr) string {
	frames := runtime.CallersFrames(pcs)
	var names []string
	for len(names) < 3 {
		frame, more := frames.Next()
		if fn := frame.Function; fn != "" && !strings.HasPrefix(fn, "database/sql.") && !strings.HasPrefix(fn, "runtime.") {
			names = append(names, fn[strings.LastIndexByte(fn, '/')+1:])
		}
		if !more {
			break
		}
	}
	return strings.Join(names, " < ")
}
