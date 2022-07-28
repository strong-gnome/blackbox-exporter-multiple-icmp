// Copyright 2016 The Prometheus Authors
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
	"bytes"
	"context"
	"math/rand"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/prometheus/blackbox_exporter/config"
)

var (
	icmp_duration_rtt  []int
	icmp_reply_ttl     []int
	icmp_success_probe []int
	locker             sync.Mutex
	isSuccess          bool
	icmp_aver_rtt      float32
	icmp_aver_ttl      int
	icmp_packet_loss   float32
	icmp_jitterMax     float32 = 0
	icmp_jitterMin     float32 = 0
)

func get_icmp_meta() (int, uint16) {
	var icmpID int
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	// Set the ICMP echo ID to a random value to avoid potential clashes with
	// other blackbox_exporter instances. See #411.
	icmpID = r.Intn(1 << 16)

	// Start the ICMP echo sequence at a random offset to prevent them from
	// being in sync when several blackbox_exporter instances are restarted
	// at the same time. See #411.
	icmpSequence := uint16(r.Intn(1 << 16))

	return icmpID, icmpSequence
}

func locking_fn(locked_var []int, appendix int) []int {
	locker.Lock()
	defer locker.Unlock()
	locked_var = append(locked_var, appendix)
	return locked_var
}

// Main func to initiate icmp probe or probes - depends on "packets" value.
func ProbeICMP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger) (success bool) {
	var (
		packets       int
		wg            sync.WaitGroup
		durationGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_icmp_rtt_milliseconds",
			Help: "Round Trip Time (ms) for icmp probe",
		})

		ttlGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_icmp_reply_ttl",
			Help: "Replied packet hop limit for ipv6 (TTL for ipv4)",
		})

		packetLossGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_icmp_packet_loss",
			Help: "Percent of lost packets or failed attempts (due to any reason)",
		})
		packetsGauge = prometheus.NewGauge((prometheus.GaugeOpts{
			Name: "probe_icmp_packets",
			Help: "How many packets are being send per query",
		}))
		jitterMaxGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_icmp_jitterMax",
			Help: "Returns jitter between highest and lowest RTT in series (works only if packets are more than 1)",
		})
	)

	dstIPAddr, _, err := chooseProtocol(ctx, module.ICMP.IPProtocol, module.ICMP.IPProtocolFallback, target, registry, logger)

	if err != nil {
		level.Warn(logger).Log("msg", "Error resolving address", "err", err)
		return false
	}

	packets = module.ICMP.Packets

	registry.MustRegister(durationGauge)
	registry.MustRegister(ttlGauge)
	registry.MustRegister(packetLossGauge)
	registry.MustRegister(packetsGauge)
	if packets > 1 {
		registry.MustRegister(jitterMaxGauge)
	}

	MultipleICMP(ctx, module, logger, &wg, dstIPAddr, packets)

	durationGauge.Add(float64(icmp_aver_rtt))
	ttlGauge.Add(float64(icmp_aver_ttl))
	packetLossGauge.Add(float64(icmp_packet_loss))
	packetsGauge.Add(float64(packets))
	if packets > 1 {
		jitterMaxGauge.Add(float64(icmp_jitterMax))
	}

	icmp_duration_rtt = nil
	icmp_reply_ttl = nil
	icmp_success_probe = nil

	return isSuccess
}

// Handle few icmp probes concurrently and count packet loss percent
func MultipleICMP(ctx context.Context, module config.Module, logger log.Logger, wg *sync.WaitGroup, dstIPAddr *net.IPAddr, packets int) {
	var (
		summ_value float32
		len_values int
		max_value  int = 0
		min_value  int = 10000
	)

	// Run multiple probes (or just one)
	for x := 0; x < packets; x++ {
		wg.Add(1)
		time.Sleep(time.Duration(x+1) * time.Millisecond)
		go ProbeSingleICMP(ctx, module, logger, wg, dstIPAddr)
	}

	// Start to calculate average value of packet loss + success for the probe at all
	summ_value = 0
	len_values = len(icmp_success_probe)
	for _, probe := range icmp_success_probe {
		summ_value += float32(probe)
	}
	if summ_value > 0 {
		isSuccess = true
		icmp_packet_loss = 100 - summ_value/float32(len_values)*100
	} else {
		isSuccess = false
		icmp_packet_loss = 100
	}

	// Start to calculate average value of rtt
	summ_value = 0
	len_values = len(icmp_duration_rtt)
	for _, rtt := range icmp_duration_rtt {
		summ_value += float32(rtt)
		if rtt > max_value {
			max_value = rtt
		}
		if rtt < min_value {
			min_value = rtt
		}
	}
	icmp_aver_rtt = summ_value / float32(len_values)

	// Start to calculate average value of ttl on returned packets
	summ_value = 0
	len_values = len(icmp_reply_ttl)
	for _, ttl := range icmp_reply_ttl {
		summ_value += float32(ttl)
	}
	icmp_aver_ttl = int(summ_value / float32(len_values))

	// Start to calculate jitter
	icmp_jitterMax = float32(max_value) - float32(min_value)

	return
}

// Run single icmp probe
func ProbeSingleICMP(ctx context.Context, module config.Module, logger log.Logger, wg *sync.WaitGroup, dstIPAddr *net.IPAddr) {
	var (
		requestType     icmp.Type
		replyType       icmp.Type
		icmpConn        *icmp.PacketConn
		v4RawConn       *ipv4.RawConn
		hopLimitFlagSet bool = true
		err             error
	)

	var srcIP net.IP
	if len(module.ICMP.SourceIPAddress) > 0 {
		if srcIP = net.ParseIP(module.ICMP.SourceIPAddress); srcIP == nil {
			level.Error(logger).Log("msg", "Error parsing source ip address", "srcIP", module.ICMP.SourceIPAddress)
			icmp_success_probe = locking_fn(icmp_success_probe, 0)
			wg.Done()
			return
		}
		level.Info(logger).Log("msg", "Using source address", "srcIP", srcIP)
	}

	level.Info(logger).Log("msg", "Creating socket")

	privileged := true
	// Unprivileged sockets are supported on Darwin and Linux only.
	tryUnprivileged := runtime.GOOS == "darwin" || runtime.GOOS == "linux"

	if dstIPAddr.IP.To4() == nil {
		requestType = ipv6.ICMPTypeEchoRequest
		replyType = ipv6.ICMPTypeEchoReply

		if srcIP == nil {
			srcIP = net.ParseIP("::")
		}

		if tryUnprivileged {
			// "udp" here means unprivileged -- not the protocol "udp".
			icmpConn, err = icmp.ListenPacket("udp6", srcIP.String())
			if err != nil {
				level.Debug(logger).Log("msg", "Unable to do unprivileged listen on socket, will attempt privileged", "err", err)
			} else {
				privileged = false
			}
		}

		if privileged {
			icmpConn, err = icmp.ListenPacket("ip6:ipv6-icmp", srcIP.String())
			if err != nil {
				level.Error(logger).Log("msg", "Error listening to socket", "err", err)
				icmp_success_probe = locking_fn(icmp_success_probe, 0)
				wg.Done()
				return
			}
		}
		defer icmpConn.Close()

		if err := icmpConn.IPv6PacketConn().SetControlMessage(ipv6.FlagHopLimit, true); err != nil {
			level.Debug(logger).Log("msg", "Failed to set Control Message for retrieving Hop Limit", "err", err)
			hopLimitFlagSet = false
		}
	} else {
		requestType = ipv4.ICMPTypeEcho
		replyType = ipv4.ICMPTypeEchoReply

		if srcIP == nil {
			srcIP = net.ParseIP("0.0.0.0")
		}

		if module.ICMP.DontFragment {
			// If the user has set the don't fragment option we cannot use unprivileged
			// sockets as it is not possible to set IP header level options.
			netConn, err := net.ListenPacket("ip4:icmp", srcIP.String())
			if err != nil {
				level.Error(logger).Log("msg", "Error listening to socket", "err", err)
				icmp_success_probe = locking_fn(icmp_success_probe, 0)
				wg.Done()
				return
			}
			defer netConn.Close()

			v4RawConn, err = ipv4.NewRawConn(netConn)
			if err != nil {
				level.Error(logger).Log("msg", "Error creating raw connection", "err", err)
				icmp_success_probe = locking_fn(icmp_success_probe, 0)
				wg.Done()
				return
			}
			defer v4RawConn.Close()

			if err := v4RawConn.SetControlMessage(ipv4.FlagTTL, true); err != nil {
				level.Debug(logger).Log("msg", "Failed to set Control Message for retrieving TTL", "err", err)
				hopLimitFlagSet = false
			}
		} else {
			if tryUnprivileged {
				icmpConn, err = icmp.ListenPacket("udp4", srcIP.String())
				if err != nil {
					level.Debug(logger).Log("msg", "Unable to do unprivileged listen on socket, will attempt privileged", "err", err)
				} else {
					privileged = false
				}
			}

			if privileged {
				icmpConn, err = icmp.ListenPacket("ip4:icmp", srcIP.String())
				if err != nil {
					level.Error(logger).Log("msg", "Error listening to socket", "err", err)
					icmp_success_probe = locking_fn(icmp_success_probe, 0)
					wg.Done()
					return
				}
			}
			defer icmpConn.Close()

			if err := icmpConn.IPv4PacketConn().SetControlMessage(ipv4.FlagTTL, true); err != nil {
				level.Debug(logger).Log("msg", "Failed to set Control Message for retrieving TTL", "err", err)
				hopLimitFlagSet = false
			}
		}
	}

	var dst net.Addr = dstIPAddr
	if !privileged {
		dst = &net.UDPAddr{IP: dstIPAddr.IP, Zone: dstIPAddr.Zone}
	}

	var data []byte
	if module.ICMP.PayloadSize != 0 {
		data = make([]byte, module.ICMP.PayloadSize)
		copy(data, "Prometheus Blackbox Exporter")
	} else {
		data = []byte("Prometheus Blackbox Exporter")
	}
	icmpID, icmpSequence := get_icmp_meta()
	body := &icmp.Echo{
		ID:   icmpID,
		Seq:  int(icmpSequence),
		Data: data,
	}
	level.Info(logger).Log("msg", "Creating ICMP packet", "seq", body.Seq, "id", body.ID)
	wm := icmp.Message{
		Type: requestType,
		Code: 0,
		Body: body,
	}

	wb, err := wm.Marshal(nil)
	if err != nil {
		level.Error(logger).Log("msg", "Error marshalling packet", "err", err)
		icmp_success_probe = locking_fn(icmp_success_probe, 0)
		wg.Done()
		return
	}

	level.Info(logger).Log("msg", "Writing out packet")
	rttStart := time.Now()

	if icmpConn != nil {
		ttl := module.ICMP.TTL
		if ttl > 0 {
			if c4 := icmpConn.IPv4PacketConn(); c4 != nil {
				level.Debug(logger).Log("msg", "Setting TTL (IPv4 unprivileged)", "ttl", ttl)
				c4.SetTTL(ttl)
			}
			if c6 := icmpConn.IPv6PacketConn(); c6 != nil {
				level.Debug(logger).Log("msg", "Setting TTL (IPv6 unprivileged)", "ttl", ttl)
				c6.SetHopLimit(ttl)
			}
		}
		_, err = icmpConn.WriteTo(wb, dst)
	} else {
		ttl := config.DefaultICMPTTL
		if module.ICMP.TTL > 0 {
			level.Debug(logger).Log("msg", "Overriding TTL (raw IPv4)", "ttl", ttl)
			ttl = module.ICMP.TTL
		}
		// Only for IPv4 raw. Needed for setting DontFragment flag.
		header := &ipv4.Header{
			Version:  ipv4.Version,
			Len:      ipv4.HeaderLen,
			Protocol: 1,
			TotalLen: ipv4.HeaderLen + len(wb),
			TTL:      ttl,
			Dst:      dstIPAddr.IP,
			Src:      srcIP,
		}

		header.Flags |= ipv4.DontFragment

		err = v4RawConn.WriteTo(header, wb, nil)
	}
	if err != nil {
		level.Warn(logger).Log("msg", "Error writing to socket", "err", err)
		icmp_success_probe = locking_fn(icmp_success_probe, 0)
		wg.Done()
		return
	}

	// Reply should be the same except for the message type and ID if
	// unprivileged sockets were used and the kernel used its own.
	wm.Type = replyType
	// Unprivileged cannot set IDs on Linux.
	idUnknown := !privileged && runtime.GOOS == "linux"
	if idUnknown {
		body.ID = 0
	}
	wb, err = wm.Marshal(nil)
	if err != nil {
		level.Error(logger).Log("msg", "Error marshalling packet", "err", err)
		icmp_success_probe = locking_fn(icmp_success_probe, 0)
		wg.Done()
		return
	}

	if idUnknown {
		// If the ID is unknown (due to unprivileged sockets) we also cannot know
		// the checksum in userspace.
		wb[2] = 0
		wb[3] = 0
	}

	rb := make([]byte, 65536)
	deadline, _ := ctx.Deadline()
	if icmpConn != nil {
		err = icmpConn.SetReadDeadline(deadline)
	} else {
		err = v4RawConn.SetReadDeadline(deadline)
	}
	if err != nil {
		level.Error(logger).Log("msg", "Error setting socket deadline", "err", err)
		icmp_success_probe = locking_fn(icmp_success_probe, 0)
		wg.Done()
		return
	}
	level.Info(logger).Log("msg", "Waiting for reply packets")
	for {
		var n int
		var peer net.Addr
		var err error
		var hopLimit float64 = -1

		if dstIPAddr.IP.To4() == nil {
			var cm *ipv6.ControlMessage
			n, cm, peer, err = icmpConn.IPv6PacketConn().ReadFrom(rb)
			// HopLimit == 0 is valid for IPv6, although go initialize it as 0.
			if cm != nil && hopLimitFlagSet {
				hopLimit = float64(cm.HopLimit)
			} else {
				level.Debug(logger).Log("msg", "Cannot get Hop Limit from the received packet. 'probe_icmp_reply_ttl' will be missing.")
			}
		} else {
			var cm *ipv4.ControlMessage
			if icmpConn != nil {
				n, cm, peer, err = icmpConn.IPv4PacketConn().ReadFrom(rb)
			} else {
				var h *ipv4.Header
				var p []byte
				h, p, cm, err = v4RawConn.ReadFrom(rb)
				if err == nil {
					copy(rb, p)
					n = len(p)
					peer = &net.IPAddr{IP: h.Src}
				}
			}
			if cm != nil && hopLimitFlagSet {
				// Not really Hop Limit, but it is in practice.
				hopLimit = float64(cm.TTL)
			} else {
				level.Debug(logger).Log("msg", "Cannot get TTL from the received packet. 'probe_icmp_reply_ttl' will be missing.")
			}
		}
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				level.Warn(logger).Log("msg", "Timeout reading from socket", "err", err)
				icmp_success_probe = locking_fn(icmp_success_probe, 0)
				wg.Done()
				return
			}
			level.Error(logger).Log("msg", "Error reading from socket", "err", err)
			continue
		}
		if peer.String() != dst.String() {
			continue
		}
		if idUnknown {
			// Clear the ID from the packet, as the kernel will have replaced it (and
			// kept track of our packet for us, hence clearing is safe).
			rb[4] = 0
			rb[5] = 0
		}
		if idUnknown || replyType == ipv6.ICMPTypeEchoReply {
			// Clear checksum to make comparison succeed.
			rb[2] = 0
			rb[3] = 0
		}
		if bytes.Equal(rb[:n], wb) {
			icmp_duration_rtt = locking_fn(icmp_duration_rtt, int(time.Since(rttStart).Milliseconds()))
			if hopLimit >= 0 {
				icmp_reply_ttl = locking_fn(icmp_reply_ttl, int(hopLimit))
			}
			level.Info(logger).Log("msg", "Found matching reply packet")
			icmp_success_probe = locking_fn(icmp_success_probe, 1)
			wg.Done()
			return
		}
	}
}
