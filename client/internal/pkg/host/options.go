package host

import "log/slog"

// Options for [*HostLoginHandler]
type HostLoginHandlerOption func(*HostLoginHandler)

// WithHostLogger allows providing a custom [*slog.Logger] for the service
func WithHostLogger(logger *slog.Logger) HostLoginHandlerOption {
	return func(lh *HostLoginHandler) {
		lh.logger = logger
	}
}
