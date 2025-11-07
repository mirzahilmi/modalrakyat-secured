package logging

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	stdlog "log"
)

func Init(logLevel string) {
	log.Logger = zerolog.New(os.Stdout).
		With().
		Stack().
		Timestamp().Logger()

	level, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		stdlog.Panicf(`logging: failed to parse log level of %s: %v`, logLevel, err)
	}
	zerolog.SetGlobalLevel(level)
}
