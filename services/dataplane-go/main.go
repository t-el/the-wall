package main

import (
	"bufio"
	"encoding/json"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	lua "github.com/yuin/gopher-lua"
)

// Production Data Plane — Go + Lua
// TCP 5140 + UDP 514 ingestion, isolated Lua playbooks, NATS remediation

type Playbook struct {
	Name string
	L    *lua.LState
}

type Engine struct {
	mu        sync.RWMutex
	playbooks []*Playbook
}

func NewEngine() *Engine { return &Engine{} }

func (e *Engine) LoadDirectory(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Printf("playbooks dir %s: %v", dir, err)
		return 0
	}
	count := 0
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".lua") {
			continue
		}
		path := filepath.Join(dir, ent.Name())
		src, err := os.ReadFile(path)
		if err != nil {
			log.Printf("read %s: %v", path, err)
			continue
		}
		name := strings.TrimSuffix(ent.Name(), ".lua")
		L := lua.NewState()
		L.SetGlobal("log_info", L.NewFunction(func(L *lua.LState) int {
			log.Printf("[lua:%s] %s", name, L.CheckString(1))
			return 0
		}))
		L.SetGlobal("log_warn", L.NewFunction(func(L *lua.LState) int {
			log.Printf("[lua:%s] WARN %s", name, L.CheckString(1))
			return 0
		}))
		if err := L.DoString(string(src)); err != nil {
			log.Printf("load playbook %s: %v", name, err)
			L.Close()
			continue
		}
		e.mu.Lock()
		e.playbooks = append(e.playbooks, &Playbook{Name: name, L: L})
		e.mu.Unlock()
		log.Printf("loaded playbook %s", name)
		count++
	}
	log.Printf("%d playbooks loaded from %s", count, dir)
	return count
}

func (e *Engine) Evaluate(event map[string]interface{}) []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var matched []string
	for _, pb := range e.playbooks {
		fn := pb.L.GetGlobal("evaluate_threat")
		if fn == lua.LNil {
			continue
		}
		tbl := pb.L.NewTable()
		for k, v := range event {
			switch val := v.(type) {
			case string:
				tbl.RawSetString(k, lua.LString(val))
			case float64:
				tbl.RawSetString(k, lua.LNumber(val))
			case bool:
				tbl.RawSetString(k, lua.LBool(val))
			}
		}
		pb.L.Push(fn)
		pb.L.Push(tbl)
		if err := pb.L.PCall(1, 1, nil); err != nil {
			log.Printf("playbook %s eval: %v", pb.Name, err)
			continue
		}
		ret := pb.L.Get(-1)
		pb.L.Pop(1)
		if ret == lua.LTrue {
			matched = append(matched, pb.Name)
			if rem := pb.L.GetGlobal("remediate"); rem != lua.LNil {
				pb.L.Push(rem)
				pb.L.Push(tbl)
				_ = pb.L.PCall(1, 0, nil)
			}
		}
	}
	return matched
}

type MarkerEvaluator struct {
	markers map[string]struct{}
}

func NewMarkerEvaluator() *MarkerEvaluator {
	m := map[string]struct{}{
		"sckit": {}, "scscreenconnect": {}, "rmm+": {},
		"mimikatz": {}, "procdump": {}, "cmd.aspx": {},
	}
	if env := os.Getenv("DGSSI_MARKERS"); env != "" {
		for _, part := range strings.Split(env, ",") {
			m[strings.ToLower(strings.TrimSpace(part))] = struct{}{}
		}
	}
	return &MarkerEvaluator{markers: m}
}

func (m *MarkerEvaluator) Hit(event map[string]interface{}) bool {
	fields := []string{"payload", "cmdline", "process_name", "file_name", "dst_domain", "url"}
	for _, f := range fields {
		if s, ok := event[f].(string); ok {
			lower := strings.ToLower(s)
			for mk := range m.markers {
				if strings.Contains(lower, mk) {
					return true
				}
			}
		}
	}
	return false
}

func process(event map[string]interface{}, eng *Engine, markers *MarkerEvaluator, nc *nats.Conn) {
	markerHit := markers.Hit(event)
	playbooks := eng.Evaluate(event)
	if !markerHit && len(playbooks) == 0 {
		return
	}
	log.Printf("THREAT marker=%v playbooks=%v", markerHit, playbooks)

	sev := "medium"
	if markerHit {
		sev = "high"
	}
	class, _ := event["asset_class"].(string)
	if class == "" {
		class = "B"
	}
	tenant, _ := event["tenant_id"].(string)
	if tenant == "" {
		tenant = "default"
	}
	payload := map[string]interface{}{
		"action":          "contain",
		"source":          "dataplane",
		"marker_hit":      markerHit,
		"playbooks":       playbooks,
		"event":           event,
		"timestamp":       time.Now().UTC().Format(time.RFC3339),
		"severity":        sev,
		"requires_macert": class == "A" || markerHit,
		"tenant_id":       tenant,
		"asset_class":     class,
	}
	b, _ := json.Marshal(payload)
	if err := nc.Publish("thewall.remediation", b); err != nil {
		log.Printf("nats publish: %v", err)
	} else {
		log.Println("remediation published")
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("The Wall Data Plane (Go) starting")

	dir := os.Getenv("PLAYBOOKS_DIR")
	if dir == "" {
		dir = "/etc/the-wall/playbooks"
	}
	if _, err := os.Stat(dir); err != nil {
		dir = "../../scripts/playbooks-lua"
	}
	eng := NewEngine()
	eng.LoadDirectory(dir)

	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = nats.DefaultURL
	}
	nc, err := nats.Connect(natsURL)
	if err != nil {
		log.Fatalf("nats: %v", err)
	}
	defer nc.Close()
	log.Printf("NATS connected %s", natsURL)

	markers := NewMarkerEvaluator()

	go func() {
		ln, err := net.Listen("tcp", ":5140")
		if err != nil {
			log.Fatal(err)
		}
		log.Println("TCP listening :5140")
		for {
			conn, err := ln.Accept()
			if err != nil {
				continue
			}
			go func(c net.Conn) {
				defer c.Close()
				sc := bufio.NewScanner(c)
				for sc.Scan() {
					line := strings.TrimSpace(sc.Text())
					if line == "" {
						continue
					}
					var ev map[string]interface{}
					if json.Unmarshal([]byte(line), &ev) == nil {
						process(ev, eng, markers, nc)
					}
				}
			}(conn)
		}
	}()

	go func() {
		addr, _ := net.ResolveUDPAddr("udp", ":514")
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("UDP listening :514")
		buf := make([]byte, 8192)
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			line := strings.TrimSpace(string(buf[:n]))
			var ev map[string]interface{}
			if json.Unmarshal([]byte(line), &ev) == nil {
				process(ev, eng, markers, nc)
			}
		}
	}()

	log.Println("data plane ready")
	select {}
}
