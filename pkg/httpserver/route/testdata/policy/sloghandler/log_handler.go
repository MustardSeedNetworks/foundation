package sse

// A slog.Handler wrapper forwards records with a Handle call that registers
// no route.
func (h *logHandler) Handle(ctx context.Context, rec slog.Record) error {
	h.publish(rec)
	return h.next.Handle(ctx, rec)
}
