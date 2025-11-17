package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/danielgtaylor/huma/v2/humacli"
	"github.com/go-chi/chi/v5"
	"github.com/mirzahilmi/modalrakyat-hardened/internal/common/config"
	"github.com/mirzahilmi/modalrakyat-hardened/internal/common/constant"
	"github.com/mirzahilmi/modalrakyat-hardened/internal/common/logging"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

type options struct {
	LogLevel   string `doc:"Log verbosity level" default:"info"`
	ConfigPath string `doc:"Configuration path [REQUIRED]" name:"config"`
}

var (
	api huma.API
	cfg config.Config
)

func main() {
	cli := humacli.New(func(hooks humacli.Hooks, options *options) {
		logging.Init(options.LogLevel)

		if options.ConfigPath == "" {
			log.Fatal().Msg("config: missing CONFIG_PATH")
		}
		configBytes, err := os.ReadFile(options.ConfigPath)
		if err != nil {
			log.Fatal().Err(err).Msg(fmt.Sprintf("config: cannot read file %s", options.ConfigPath))
		}
		if err := json.NewDecoder(bytes.NewBuffer(configBytes)).Decode(&cfg); err != nil {
			log.Fatal().Err(err).Msg("config: failed to parse config raw bytes to struct")
		}
		ctx := context.Background()

		oapi := huma.DefaultConfig("ModelRakyat - OpenAPI 3.0", "1.0.0")
		oapi.DocsPath = ""
		oapi.Info.Description = constant.OAPI_SPEC_DESCRIPTION
		oapi.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
			constant.OAPI_SECURITY_SCHEME: {
				Type: "oauth2",
				Flows: &huma.OAuthFlows{
					Implicit: &huma.OAuthFlow{
						AuthorizationURL: fmt.Sprintf(
							"%s/protocol/openid-connect/auth",
							cfg.Oidc.Issuer,
						),
						Scopes: map[string]string{
							"openid": "openid",
						},
						Extensions: map[string]any{
							"x-defaultClientId": cfg.Oidc.ClientId,
						},
					},
				},
			},
		}
		oapi.Security = []map[string][]string{
			{constant.OAPI_SECURITY_SCHEME: {}},
		}

		router := chi.NewRouter()
		if cfg.IsDevelopment {
			router.Get("/docs", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				if _, err := w.Write([]byte(constant.OAPI_SPEC_UI)); err != nil {
					log.Debug().Err(err).Msg("docs: failed to write openapi editor ui")
				}
			})
		}

		api = humachi.New(router, oapi)
		close, err := setup(ctx)
		if err != nil {
			log.Fatal().Err(err).Msg("app: failed to setup")
		}

		addr := fmt.Sprintf(":%d", cfg.Port)
		server := http.Server{
			Addr:              addr,
			Handler:           router,
			ReadHeaderTimeout: 5 * time.Second, // mitigate slowloris attacks
		}

		hooks.OnStart(func() {
			log.Info().Msg(fmt.Sprintf("http: listening on 0.0.0.0%s", addr))
			if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				log.Fatal().Err(err).Msg(fmt.Sprintf("http: failed to listen on 0.0.0.0%s", addr))
			}
		})

		hooks.OnStop(func() {
			ctx, cancel := context.WithTimeout(
				context.Background(),
				time.Duration(cfg.ShutdownTimeout)*time.Second,
			)
			defer cancel()

			if err := server.Shutdown(ctx); err != nil {
				log.Fatal().Err(err).Msg("http: failed to shutdown")
			}
			if err := close(); err != nil {
				log.Fatal().Err(err).Msg("http: failed to shutdown")
			}
			log.Info().Msg("http: shut down complete")
		})
	})

	cli.Root().AddCommand(&cobra.Command{
		Use:   "spec",
		Short: "Print the OpenAPI specification",
		RunE: func(cmd *cobra.Command, args []string) error {
			var spec []byte
			if len(args) == 1 && args[0] == "legacy" {
				raw, err := api.OpenAPI().DowngradeYAML()
				if err != nil {
					return err
				}
				spec = raw
			} else {
				raw, err := api.OpenAPI().YAML()
				if err != nil {
					return err
				}
				spec = raw
			}
			fmt.Println(string(spec))

			return nil
		},
	})

	cli.Run()
}
