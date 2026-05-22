package telemetry

import (
	"context"

	"github.com/ClickHouse/clickhouse-go/v2"
)

type ClickHouseLogger struct {
	conn clickhouse.Conn
}

func NewClickHouseLogger(addr string) (*ClickHouseLogger, error) {
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{
			Database: "default",
			Username: "default",
			Password: "",
		},
	})
	if err != nil {
		return nil, err
	}
	return &ClickHouseLogger{conn: conn}, nil
}

func (l *ClickHouseLogger) InitSchema() error {
	return l.conn.Exec(context.Background(), `
		CREATE TABLE IF NOT EXISTS security_events (
			timestamp DateTime,
			request_id String,
			tenant_id String,
			remote_addr String,
			method String,
			url String,
			score Int32,
			action String
		) ENGINE = MergeTree()
		ORDER BY timestamp
	`)
}
