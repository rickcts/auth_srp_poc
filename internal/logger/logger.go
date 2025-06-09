package logger

import (
	"io"
	stdlog "log"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Init initializes the global zerolog logger.
func Init(logLevelStr string, appEnv string) {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	parsedLevel, err := zerolog.ParseLevel(strings.ToLower(logLevelStr))
	if err != nil {
		parsedLevel = zerolog.InfoLevel
		log.Warn().Err(err).Msgf("Invalid log level '%s', defaulting to 'info'", logLevelStr)
	}
	zerolog.SetGlobalLevel(parsedLevel)

	var output io.Writer = os.Stdout
	if strings.ToLower(appEnv) == "development" || strings.ToLower(appEnv) == "dev" {
		output = zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	}

	log.Logger = zerolog.New(output).With().Timestamp().Logger()

	stdlog.SetFlags(0)
	stdlog.SetOutput(log.Logger)
}
