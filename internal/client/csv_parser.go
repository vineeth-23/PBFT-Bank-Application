package client

import (
	"encoding/csv"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	pb "pbft-bank-application/pbft-bank-application/proto"
)

type Attack struct {
	Name  string
	Nodes []int32
}

type Set struct {
	Number  int32
	Txs     []*pb.Transaction
	Live    []int32
	Byz     []int32
	Attacks []*Attack
}

var (
	txTripleRe = regexp.MustCompile(`^\(\s*([A-J])\s*,\s*([A-J])\s*,\s*(\d+)\s*\)$`)

	txSingleRe = regexp.MustCompile(`^\(\s*([A-J])\s*\)$`)

	bracketStrip = regexp.MustCompile(`^\[\s*|\s*\]$`)

	attackNameOnlyRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)
	attackWithNodesRe = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_-]*)\s*\(\s*([nN]\d+(?:\s*,\s*[nN]\d+)*)\s*\)$`)

	nodeTokenRe = regexp.MustCompile(`^[nN](\d+)$`)
)

func ParseCSVStrict(path string) ([]*Set, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.TrimLeadingSpace = true
	r.FieldsPerRecord = 5

	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) <= 1 {
		return nil, fmt.Errorf("no data rows")
	}

	var sets []*Set
	var cur *Set
	var globalTime int32 = 1

	for i := 1; i < len(rows); i++ {
		rec := rows[i]
		setNumStr := strings.TrimSpace(rec[0])
		txStr := strings.TrimSpace(rec[1])
		liveStr := strings.TrimSpace(rec[2])
		byzStr := strings.TrimSpace(rec[3])
		attackStr := strings.TrimSpace(rec[4])

		if setNumStr != "" {
			n, err := strconv.Atoi(setNumStr)
			if err != nil {
				return nil, fmt.Errorf("bad set number %q at row %d", setNumStr, i+1)
			}
			cur = &Set{Number: int32(n)}

			if liveStr != "" {
				liveIDs, err := parseNodeIDsBracketed(liveStr)
				if err != nil {
					return nil, fmt.Errorf("row %d live: %w", i+1, err)
				}
				cur.Live = liveIDs
			}
			if byzStr != "" {
				byzIDs, err := parseNodeIDsBracketed(byzStr)
				if err != nil {
					return nil, fmt.Errorf("row %d byzantine: %w", i+1, err)
				}
				cur.Byz = byzIDs
			}
			if attackStr != "" {
				attacks, err := parseAttacks(attackStr)
				if err != nil {
					return nil, fmt.Errorf("row %d attacks: %w", i+1, err)
				}
				cur.Attacks = attacks
			}

			sets = append(sets, cur)
		}

		if cur == nil {
			return nil, fmt.Errorf("transactions encountered before first set at row %d", i+1)
		}

		if txStr == "" {
			continue
		}

		tx, err := parseOneTxStrict(txStr)
		if err != nil {
			return nil, fmt.Errorf("row %d: %w", i+1, err)
		}

		tx.Time = globalTime
		globalTime++

		cur.Txs = append(cur.Txs, tx)
	}

	return sets, nil
}

func parseOneTxStrict(s string) (*pb.Transaction, error) {
	if m := txTripleRe.FindStringSubmatch(s); m != nil {
		amt, _ := strconv.Atoi(m[3])
		return &pb.Transaction{
			FromClientId: m[1],
			ToClientId:   m[2],
			Amount:       int32(amt),
			Time:         0,
		}, nil
	}
	if m := txSingleRe.FindStringSubmatch(s); m != nil {
		id := m[1]
		return &pb.Transaction{
			FromClientId: id,
			ToClientId:   id,
			Amount:       -1,
			Time:         0,
		}, nil
	}
	return nil, fmt.Errorf("invalid transaction syntax %q", s)
}

func parseNodeIDsBracketed(s string) ([]int32, error) {
	s = bracketStrip.ReplaceAllString(s, "")
	if s == "" {
		return nil, nil
	}
	return parseNodeIDs(s)
}

func parseAttacks(s string) ([]*Attack, error) {
	s = bracketStrip.ReplaceAllString(s, "")
	if s == "" {
		return nil, nil
	}
	raw := strings.Split(s, ";")
	out := make([]*Attack, 0, len(raw))

	for _, t := range raw {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}

		if m := attackWithNodesRe.FindStringSubmatch(t); m != nil {
			name := m[1]
			nodesStr := m[2]
			ids, err := parseNodeIDs(nodesStr)
			if err != nil {
				return nil, fmt.Errorf("attack %q: %w", t, err)
			}
			out = append(out, &Attack{Name: name, Nodes: ids})
			continue
		}

		if attackNameOnlyRe.MatchString(t) {
			out = append(out, &Attack{Name: t, Nodes: nil})
			continue
		}

		return nil, fmt.Errorf("invalid attack token %q", t)
	}

	return out, nil
}

func parseNodeIDs(list string) ([]int32, error) {
	parts := strings.Split(list, ",")
	var ids []int32
	for _, p := range parts {
		p = strings.TrimSpace(p)
		m := nodeTokenRe.FindStringSubmatch(p)
		if m == nil {
			return nil, fmt.Errorf("bad node %q, want n<number>", p)
		}
		v, err := strconv.Atoi(m[1])
		if err != nil {
			return nil, fmt.Errorf("bad node number %q", m[1])
		}
		ids = append(ids, int32(v))
	}
	return ids, nil
}
