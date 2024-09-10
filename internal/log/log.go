package log

// basically, just a `log/slog` wrapper to add the `Fatal`/`FatalContext` function, and add a Logger Level selector

import (
	"context"
	"log/slog"
	"os"
)

var logLvl = new(slog.LevelVar)

func InitDefault(level slog.Level) {
	logLvl.Set(level)
	lh := slog.NewTextHandler(
		os.Stderr,
		&slog.HandlerOptions{
			AddSource: true,
			Level:     logLvl,
		},
	)
	logger := slog.New(lh)
	slog.SetDefault(logger)
}

func GetLogLevel() slog.Level {
	return logLvl.Level()
}

func SetLogLevel(level slog.Level) {
	logLvl.Set(level)
}

func Debug(msg string, args ...any) {
	slog.Debug(msg, args...)
}
func DebugContext(ctx context.Context, msg string, args ...any) {
	slog.DebugContext(ctx, msg, args...)
}
func Info(msg string, args ...any) {
	slog.Info(msg, args...)
}
func InfoContext(ctx context.Context, msg string, args ...any) {
	slog.InfoContext(ctx, msg, args...)
}
func Error(msg string, args ...any) {
	slog.Error(msg, args...)
}
func ErrorContext(ctx context.Context, msg string, args ...any) {
	slog.ErrorContext(ctx, msg, args...)
}
func Warn(msg string, args ...any) {
	slog.Warn(msg, args...)
}
func WarnContext(ctx context.Context, msg string, args ...any) {
	slog.WarnContext(ctx, msg, args...)
}
func Log(ctx context.Context, level slog.Level, msg string, args ...any) {
	slog.Log(ctx, level, msg, args...)
}
func LogAttrs(ctx context.Context, level slog.Level, msg string, attrs ...slog.Attr) {
	slog.LogAttrs(ctx, level, msg, attrs...)
}

func Fatal(msg string, args ...any) {
	Error(msg, args...)
	os.Exit(1)
}
func FatalContext(ctx context.Context, msg string, args ...any) {
	ErrorContext(ctx, msg, args...)
	os.Exit(1)
}

func With(args ...any) *slog.Logger { return slog.With(args...) }
