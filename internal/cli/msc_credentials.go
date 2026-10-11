package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/msc"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/spf13/cobra"
)

func newMSCCredentialsCmd(opts *Options, specPath, stateDir *string) *cobra.Command {
	root := &cobra.Command{Use: "credentials", Short: "Maintain certificates and revocation lists across local or SSH workers"}
	withEngine := func(spec *msc.Spec, fn func(*msc.Engine) error) error {
		if opts.Runtime != "" && opts.Runtime != "docker" {
			return fmt.Errorf("MSC credentials currently support Docker")
		}
		r := rt.NewDocker()
		defer func() { _ = r.Close() }()
		if err := rt.ConfigureEndpoint(r, opts.RuntimeSocket); err != nil {
			return err
		}
		e := &msc.Engine{Spec: spec, Dir: *stateDir, Runtime: r}
		unlock, err := e.Lock()
		if err != nil {
			return err
		}
		defer unlock()
		return fn(e)
	}
	var targets string
	var force, provision bool
	renew := &cobra.Command{Use: "renew", Short: "Refresh due credentials, deliver to every worker, verify loading and restore missing tunnels", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		spec, err := msc.Load(*specPath)
		if err != nil {
			return err
		}
		return withEngine(spec, func(e *msc.Engine) error {
			e.Log = cmd.ErrOrStderr()
			plan := e.LocalCredentialTargets()
			if targets != "" {
				file, err := os.Open(targets)
				if err != nil {
					return err
				}
				defer func() { _ = file.Close() }()
				decoder := json.NewDecoder(file)
				decoder.DisallowUnknownFields()
				if err = decoder.Decode(&plan); err != nil {
					return err
				}
			}
			report, err := e.RenewCredentials(cmd.Context(), plan, force, provision)
			if writeErr := json.NewEncoder(cmd.OutOrStdout()).Encode(report); writeErr != nil {
				return writeErr
			}
			return err
		})
	}}
	renew.Flags().StringVar(&targets, "targets", "", "worker/device placement JSON; default: all devices on the local worker")
	renew.Flags().BoolVar(&force, "force", false, "issue fresh CRLs even before the renewal window; preserve revocations")
	renew.Flags().BoolVar(&provision, "provision-only", false, "provision credentials before containers start; do not reload or connect")
	root.AddCommand(renew)
	apply := &cobra.Command{Use: "apply", Short: "Receive a confidential credential bundle on stdin over an authenticated operator channel", Hidden: true, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		var bundle msc.CredentialBundle
		decoder := json.NewDecoder(io.LimitReader(cmd.InOrStdin(), 32<<20))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&bundle); err != nil {
			return fmt.Errorf("invalid credential bundle JSON")
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			return fmt.Errorf("trailing credential bundle data")
		}
		if bundle.Spec == nil {
			return fmt.Errorf("missing credential specification")
		}
		return withEngine(bundle.Spec, func(e *msc.Engine) error {
			err := e.ApplyCredentialBundle(cmd.Context(), bundle, true)
			receipt := map[string]any{"at": time.Now().UTC(), "worker": bundle.Worker, "passed": err == nil, "devices": len(bundle.Devices)}
			if err != nil {
				receipt["error"] = err.Error()
			}
			body, _ := json.MarshalIndent(receipt, "", "  ")
			if writeErr := os.WriteFile(filepath.Join(e.Dir, "credential-receipt.json"), body, 0600); writeErr != nil {
				return writeErr
			}
			return err
		})
	}}
	root.AddCommand(apply)
	var devices, layer string
	connect := &cobra.Command{Use: "connect", Hidden: true, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		spec, err := msc.Load(*specPath)
		if err != nil {
			return err
		}
		return withEngine(spec, func(e *msc.Engine) error {
			return e.ConnectCredentialDevices(cmd.Context(), strings.Split(devices, ","), layer)
		})
	}}
	connect.Flags().StringVar(&devices, "devices", "", "assigned devices")
	connect.Flags().StringVar(&layer, "layer", "", "outer or inner")
	root.AddCommand(connect)
	var timerTargets string
	install := &cobra.Command{Use: "install-timer", Short: "Install hourly systemd renewal on the credential authority", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		spec, err := msc.Load(*specPath)
		if err != nil {
			return err
		}
		return withEngine(spec, func(e *msc.Engine) error {
			binary, err := os.Executable()
			if err != nil {
				return err
			}
			return e.InstallCredentialTimer(cmd.Context(), binary, *specPath, timerTargets)
		})
	}}
	install.Flags().StringVar(&timerTargets, "targets", "", "worker/device placement JSON to retain in authority state")
	root.AddCommand(install)
	return root
}
