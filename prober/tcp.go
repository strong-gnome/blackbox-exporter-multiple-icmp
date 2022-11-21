// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package prober

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	pconfig "github.com/prometheus/common/config"

	"github.com/prometheus/blackbox_exporter/config"
)

func dialTCP(ctx context.Context, target string, module config.Module, some_json *config.JSONstruct, logger log.Logger) (net.Conn, error) {
	var dialProtocol, dialTarget string
	dialer := &net.Dialer{}
	targetAddress, port, err := net.SplitHostPort(target)
	if err != nil {
		level.Error(logger).Log("msg", "Error splitting target address and port", "err", err)
		return nil, err
	}

	ip, _, err := chooseProtocol(ctx, module.TCP.IPProtocol, module.TCP.IPProtocolFallback, targetAddress, some_json, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Error resolving address", "err", err)
		return nil, err
	}

	if ip.IP.To4() == nil {
		dialProtocol = "tcp6"
	} else {
		dialProtocol = "tcp4"
	}

	if len(module.TCP.SourceIPAddress) > 0 {
		srcIP := net.ParseIP(module.TCP.SourceIPAddress)
		if srcIP == nil {
			level.Error(logger).Log("msg", "Error parsing source ip address", "srcIP", module.TCP.SourceIPAddress)
			return nil, fmt.Errorf("error parsing source ip address: %s", module.TCP.SourceIPAddress)
		}
		level.Info(logger).Log("msg", "Using local address", "srcIP", srcIP)
		dialer.LocalAddr = &net.TCPAddr{IP: srcIP}
	}

	dialTarget = net.JoinHostPort(ip.String(), port)

	if !module.TCP.TLS {
		level.Info(logger).Log("msg", "Dialing TCP without TLS")
		return dialer.DialContext(ctx, dialProtocol, dialTarget)
	}
	tlsConfig, err := pconfig.NewTLSConfig(&module.TCP.TLSConfig)
	if err != nil {
		level.Error(logger).Log("msg", "Error creating TLS configuration", "err", err)
		return nil, err
	}

	if len(tlsConfig.ServerName) == 0 {
		// If there is no `server_name` in tls_config, use
		// targetAddress as TLS-servername. Normally tls.DialWithDialer
		// would do this for us, but we pre-resolved the name by
		// `chooseProtocol` and pass the IP-address for dialing (prevents
		// resolving twice).
		// For this reason we need to specify the original targetAddress
		// via tlsConfig to enable hostname verification.
		tlsConfig.ServerName = targetAddress
	}
	timeoutDeadline, _ := ctx.Deadline()
	dialer.Deadline = timeoutDeadline

	level.Info(logger).Log("msg", "Dialing TCP with TLS")
	return tls.DialWithDialer(dialer, dialProtocol, dialTarget, tlsConfig)
}

func ProbeTCP(ctx context.Context, target string, module config.Module, some_json *config.JSONstruct, logger log.Logger) bool {

	deadline, _ := ctx.Deadline()

	conn, err := dialTCP(ctx, target, module, some_json, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Error dialing TCP", "err", err)
		return false
	}
	defer conn.Close()
	level.Info(logger).Log("msg", "Successfully dialed")

	// Set a deadline to prevent the following code from blocking forever.
	// If a deadline cannot be set, better fail the probe by returning an error
	// now rather than blocking forever.
	if err := conn.SetDeadline(deadline); err != nil {
		level.Error(logger).Log("msg", "Error setting deadline", "err", err)
		return false
	}
	if module.TCP.TLS {
		state := conn.(*tls.Conn).ConnectionState()
		Earliest_cert_expiry_date := float64(getEarliestCertExpiry(&state).Unix())
		TLS_ver := getTLSVersion(&state)
		Last_chain_expiry_timestamp := float64(getLastChainExpiry(&state).Unix())
		Leaf_cert_info := getFingerprint(&state)
		some_json.Probe_metrics = map[string]interface{}{
			"Earliest_cert_expiry_date":   Earliest_cert_expiry_date,
			"TLS_ver":                     TLS_ver,
			"Last_chain_expiry_timestamp": Last_chain_expiry_timestamp,
			"Leaf_cert_info":              Leaf_cert_info,
		}
	}
	scanner := bufio.NewScanner(conn)
	for i, qr := range module.TCP.QueryResponse {
		level.Info(logger).Log("msg", "Processing query response entry", "entry_number", i)
		send := qr.Send
		Failed_regex := "No_regex_check_passed"
		if qr.Expect.Regexp != nil {
			var match []int
			// Read lines until one of them matches the configured regexp.
			for scanner.Scan() {
				level.Debug(logger).Log("msg", "Read line", "line", scanner.Text())
				match = qr.Expect.Regexp.FindSubmatchIndex(scanner.Bytes())
				if match != nil {
					level.Info(logger).Log("msg", "Regexp matched", "regexp", qr.Expect.Regexp, "line", scanner.Text())
					break
				}
			}
			if scanner.Err() != nil {
				level.Error(logger).Log("msg", "Error reading from connection", "err", scanner.Err().Error())
				return false
			}
			if match == nil {
				Failed_regex = "true"
				level.Error(logger).Log("msg", "Regexp did not match", "regexp", qr.Expect.Regexp, "line", scanner.Text())
				return false
			}
			Failed_regex = "false"
			send = string(qr.Expect.Regexp.Expand(nil, []byte(send), scanner.Bytes(), match))
		}
		if send != "" {
			level.Debug(logger).Log("msg", "Sending line", "line", send)
			if _, err := fmt.Fprintf(conn, "%s\n", send); err != nil {
				level.Error(logger).Log("msg", "Failed to send", "err", err)
				return false
			}
		}
		if qr.StartTLS {
			// Upgrade TCP connection to TLS.
			tlsConfig, err := pconfig.NewTLSConfig(&module.TCP.TLSConfig)
			if err != nil {
				level.Error(logger).Log("msg", "Failed to create TLS configuration", "err", err)
				return false
			}
			if tlsConfig.ServerName == "" {
				// Use target-hostname as default for TLS-servername.
				targetAddress, _, _ := net.SplitHostPort(target) // Had succeeded in dialTCP already.
				tlsConfig.ServerName = targetAddress
			}
			tlsConn := tls.Client(conn, tlsConfig)
			defer tlsConn.Close()

			// Initiate TLS handshake (required here to get TLS state).
			if err := tlsConn.Handshake(); err != nil {
				level.Error(logger).Log("msg", "TLS Handshake (client) failed", "err", err)
				return false
			}
			level.Info(logger).Log("msg", "TLS Handshake (client) succeeded.")
			conn = net.Conn(tlsConn)
			scanner = bufio.NewScanner(conn)

			// Get certificate expiry.
			state := tlsConn.ConnectionState()
			Earliest_cert_expiry_date := float64(getEarliestCertExpiry(&state).Unix())
			TLS_ver := getTLSVersion(&state)
			Last_chain_expiry_timestamp := float64(getLastChainExpiry(&state).Unix())
			Leaf_cert_info := getFingerprint(&state)
			some_json.Probe_metrics = map[string]interface{}{
				"Earliest_cert_expiry_date":   Earliest_cert_expiry_date,
				"TLS_ver":                     TLS_ver,
				"Last_chain_expiry_timestamp": Last_chain_expiry_timestamp,
				"Leaf_cert_info":              Leaf_cert_info,
				"Failed_regex":                Failed_regex,
			}
		}
	}
	return true
}
