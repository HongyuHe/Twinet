package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/HongyuHe/twinet/internal/collection"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

func newCollectionCmd() *cobra.Command {
	var dir string
	root := &cobra.Command{Use: "collection", Short: "Browse, export, and transfer recorded terminal sessions"}
	root.PersistentFlags().StringVar(&dir, "dir", "", "recording directory")
	root.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if dir == "" {
			return fmt.Errorf("--dir is required")
		}
		return nil
	}
	var group, lab string
	list := &cobra.Command{Use: "list", Short: "List session metadata as JSON", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		all, err := collection.List(dir)
		if err != nil {
			return err
		}
		out := []collection.Metadata{}
		for _, m := range all {
			if (group == "" || m.Group == group) && (lab == "" || m.Lab == lab) {
				out = append(out, m)
			}
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
	}}
	list.Flags().StringVar(&group, "group", "", "filter by group")
	list.Flags().StringVar(&lab, "lab", "", "filter by lab")
	var format string
	export := &cobra.Command{Use: "export <session-id>", Short: "Export a session to stdout", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		return collection.Export(dir, args[0], format, cmd.OutOrStdout())
	}}
	export.Flags().StringVar(&format, "format", "events", "events, commands, activity, csv, coverage, or cast")
	var url, tokenFile string
	syncCmd := &cobra.Command{Use: "sync", Short: "Upload pending session data and verify completed recordings", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		token, err := collectionToken(tokenFile)
		if err != nil {
			return err
		}
		return (&collection.Uploader{Root: dir, URL: url, Token: token}).Sync(cmd.Context())
	}}
	syncCmd.Flags().StringVar(&url, "url", "", "collector URL")
	syncCmd.Flags().StringVar(&tokenFile, "token-file", "", "file containing the collector bearer token")
	var listen, serverToken, cert, key string
	var receive bool
	serve := &cobra.Command{Use: "serve", Short: "Serve the recording browser and optional upload API", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		token, err := collectionToken(serverToken)
		if err != nil {
			return err
		}
		host, _, err := net.SplitHostPort(listen)
		if err != nil {
			return err
		}
		ip := net.ParseIP(host)
		if cert == "" && (ip == nil || !ip.IsLoopback()) && host != "localhost" {
			return fmt.Errorf("non-loopback collection listeners require --tls-cert and --tls-key")
		}
		if (cert == "") != (key == "") {
			return fmt.Errorf("provide both --tls-cert and --tls-key")
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if receive {
			lock, err := os.OpenFile(filepath.Join(dir, ".writer.lock"), os.O_CREATE|os.O_RDWR, 0o600)
			if err != nil {
				return err
			}
			defer func() { _ = lock.Close() }()
			if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
				return fmt.Errorf("collection directory already has a writer: %w", err)
			}
		}
		handler, err := collection.Handler(dir, token, receive)
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		server := &http.Server{Addr: listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
		go func() {
			<-ctx.Done()
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdown)
		}()
		fmt.Fprintf(cmd.OutOrStdout(), "collection browser listening on %s\n", listen)
		if cert != "" {
			err = server.ListenAndServeTLS(cert, key)
		} else {
			err = server.ListenAndServe()
		}
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}}
	serve.Flags().StringVar(&listen, "listen", "127.0.0.1:7330", "HTTP listen address")
	serve.Flags().StringVar(&serverToken, "token-file", "", "file containing the collection access token")
	serve.Flags().BoolVar(&receive, "receive", false, "accept gateway uploads in this directory")
	serve.Flags().StringVar(&cert, "tls-cert", "", "HTTPS certificate")
	serve.Flags().StringVar(&key, "tls-key", "", "HTTPS private key")
	verify := &cobra.Command{Use: "verify", Short: "Verify journal sequences, sizes, and checksums", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		metas, err := collection.List(dir)
		if err != nil {
			return err
		}
		for _, m := range metas {
			if err := collection.Verify(dir, m.ID); err != nil {
				return err
			}
		}
		fmt.Fprintf(cmd.OutOrStdout(), "verified %d recordings\n", len(metas))
		return nil
	}}
	root.AddCommand(list, export, syncCmd, serve, verify)
	return root
}

func collectionToken(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("a collection token file is required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(b))
	if len(token) < 24 {
		return "", fmt.Errorf("collection token must contain at least 24 characters")
	}
	return token, nil
}

func uploadRecordings(ctx context.Context, u *collection.Uploader, interval time.Duration, done chan<- struct{}) {
	defer close(done)
	delay := interval
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if err := u.Sync(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("collection upload pending; local recordings retained", "error", err)
			delay = min(delay*2, time.Minute)
		} else {
			delay = interval
		}
	}
}
