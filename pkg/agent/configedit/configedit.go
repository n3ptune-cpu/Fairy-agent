// Package configedit changes one setting of fairy-agent's config.yaml in place (`fairy-agent config set`):
// yaml.v3 finds the setting's node and its position, and only that value's text is replaced (or a missing key
// is inserted under its section), so comments, blank lines, alignment, order and line endings stay exactly as
// they were. The result is decoded again and compared with the intended change before anyone writes it.
package configedit

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
)

// Setting is one leaf setting of config.yaml, e.g. fan_control.auto_mode.
type Setting struct {
	Key  string   // dotted: fan_control.auto_mode
	Path []string // [fan_control auto_mode]
	Type reflect.Type
}

// ptrDefaults are the defaults of the *bool settings (nil in the decoded Config means "the default").
var ptrDefaults = map[string]bool{"processes.enabled": true, "processes.cmdline": true, "sensors.acpi_thermal": true,
	"ipmi.sensors": true}

var (
	boolT, intT, floatT, stringT = reflect.TypeFor[bool](), reflect.TypeFor[int](), reflect.TypeFor[float64](), reflect.TypeFor[string]()
	ptrBoolT, stringsT           = reflect.TypeFor[*bool](), reflect.TypeFor[[]string]()
)

func yamlName(f reflect.StructField) string {
	n, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
	return n
}

// Settings lists every setting that `config set` can change, in config.yaml's order.
func Settings() []Setting {
	var out []Setting
	var walk func(t reflect.Type, prefix []string)
	walk = func(t reflect.Type, prefix []string) {
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			n := yamlName(f)
			if !f.IsExported() || n == "" || n == "-" {
				continue
			}
			p := append(append([]string{}, prefix...), n)
			if f.Type.Kind() == reflect.Struct {
				walk(f.Type, p)
				continue
			}
			out = append(out, Setting{Key: strings.Join(p, "."), Path: p, Type: f.Type})
		}
	}
	walk(reflect.TypeFor[agent.Config](), nil)
	return out
}

func editable(t reflect.Type) bool {
	switch t {
	case boolT, intT, floatT, stringT, ptrBoolT, stringsT:
		return true
	}
	return false
}

// Lookup finds a setting by its dotted name.
func Lookup(key string) (Setting, error) {
	var sections []string
	for _, s := range Settings() {
		if s.Key == key {
			if !editable(s.Type) {
				return s, fmt.Errorf("%s is a list of devices: edit config.yaml itself", key)
			}
			return s, nil
		}
		if strings.HasPrefix(s.Key, key+".") {
			sections = append(sections, s.Key)
		}
	}
	if len(sections) > 0 {
		return Setting{}, fmt.Errorf("%s is a section; give one of its settings: %s", key, strings.Join(sections, ", "))
	}
	return Setting{}, fmt.Errorf("unknown setting %q (`fairy-agent config show` lists them all)", key)
}

// ParseValue turns the command-line text into the setting's type: true/false, a whole number, a number, text,
// or a list (comma-separated values, or a YAML flow list like [a, b]; "" or [] is the empty list).
func ParseValue(s Setting, raw string) (any, error) {
	switch s.Type {
	case boolT, ptrBoolT:
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
		return nil, fmt.Errorf("%s must be true or false", s.Key)
	case intT:
		n, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("%s must be a whole number", s.Key)
		}
		return n, nil
	case floatT:
		f, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return nil, fmt.Errorf("%s must be a number", s.Key)
		}
		return f, nil
	case stringT:
		if strings.ContainsAny(raw, "\r\n") {
			return nil, fmt.Errorf("%s must be one line", s.Key)
		}
		return raw, nil
	case stringsT:
		t := strings.TrimSpace(raw)
		list := []string{}
		if strings.HasPrefix(t, "[") {
			if err := yaml.Unmarshal([]byte(t), &list); err != nil {
				return nil, fmt.Errorf("%s: %q is not a list like [a, b]", s.Key, raw)
			}
			return list, nil
		}
		for _, v := range strings.Split(t, ",") {
			if v = strings.TrimSpace(v); v != "" {
				list = append(list, v)
			}
		}
		return list, nil
	}
	return nil, fmt.Errorf("%s cannot be set from the command line: edit config.yaml itself", s.Key)
}

var plainSafe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_./@+-]*$`)

// Render is a value as YAML text for one line (flow style for lists; strings quoted when needed, so the same
// text is safe inside a flow mapping like {enabled: true}).
func Render(v any) (string, error) {
	switch x := v.(type) {
	case bool:
		return strconv.FormatBool(x), nil
	case int:
		return strconv.Itoa(x), nil
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), nil
	case string:
		n := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: x}
		if !plainSafe.MatchString(x) {
			n.Style = yaml.DoubleQuotedStyle
		}
		b, err := yaml.Marshal(n)
		if err != nil {
			return "", err
		}
		out := strings.TrimSuffix(string(b), "\n")
		if strings.Contains(out, "\n") {
			return "", errors.New("value must be one line")
		}
		return out, nil
	case []string:
		parts := make([]string, len(x))
		for i, s := range x {
			r, err := Render(s)
			if err != nil {
				return "", err
			}
			parts[i] = r
		}
		return "[" + strings.Join(parts, ", ") + "]", nil
	}
	return "", fmt.Errorf("cannot write a %T", v)
}

// Effective is the value the agent uses for a setting (defaults applied), as one line of text.
func Effective(cfg *agent.Config, s Setting) string {
	v := reflect.ValueOf(cfg).Elem()
	for _, p := range s.Path {
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() && yamlName(v.Type().Field(i)) == p {
				v = v.Field(i)
				break
			}
		}
	}
	switch s.Type {
	case ptrBoolT:
		if v.IsNil() {
			return strconv.FormatBool(ptrDefaults[s.Key])
		}
		return strconv.FormatBool(v.Elem().Bool())
	case stringsT:
		r, _ := Render(append([]string{}, v.Interface().([]string)...))
		return r
	case stringT:
		if v.String() == "" {
			return `""`
		}
		return v.String()
	}
	if !editable(s.Type) {
		return fmt.Sprintf("(%d entries; edit config.yaml itself)", v.Len())
	}
	r, _ := Render(v.Interface())
	return r
}

// ---------------------------------------------------------------- editing the text

// doc is config.yaml's text with yaml.v3's node positions mapped to byte offsets.
type doc struct {
	data      []byte
	lineStart []int // byte offset of each line (0-based line index)
	eol       string
	unit      int // indentation step
}

func newDoc(data []byte) *doc {
	d := &doc{data: data, eol: "\n", unit: 2, lineStart: []int{0}}
	if bytes.Contains(data, []byte("\r\n")) {
		d.eol = "\r\n"
	}
	for i, c := range data {
		if c == '\n' {
			d.lineStart = append(d.lineStart, i+1)
		}
	}
	unit := 0
	for _, l := range strings.Split(string(data), "\n") {
		t := strings.TrimLeft(l, " ")
		if n := len(l) - len(t); n > 0 && strings.TrimSpace(t) != "" && !strings.HasPrefix(t, "#") && (unit == 0 || n < unit) {
			unit = n
		}
	}
	if unit >= 1 && unit <= 8 {
		d.unit = unit
	}
	return d
}

func (d *doc) line(n int) string { // 1-based, without the line ending
	if n < 1 || n > len(d.lineStart) {
		return ""
	}
	end := len(d.data)
	if n < len(d.lineStart) {
		end = d.lineStart[n] - 1
	}
	return strings.TrimSuffix(string(d.data[d.lineStart[n-1]:end]), "\r")
}

// offset is the byte offset of a node's 1-based line and column (yaml.v3 counts characters, not bytes).
func (d *doc) offset(n *yaml.Node) (int, error) {
	if n.Line < 1 || n.Line > len(d.lineStart) {
		return 0, errors.New("position out of range")
	}
	l := d.line(n.Line)
	base := d.lineStart[n.Line-1]
	if n.Line == 1 && strings.HasPrefix(l, "\ufeff") { // UTF-8 byte order mark (Windows editors)
		l, base = l[3:], base+3
	}
	off := 0
	for col := 1; col < n.Column; col++ {
		if off >= len(l) {
			return 0, errors.New("position out of range")
		}
		_, w := utf8.DecodeRuneInString(l[off:])
		off += w
	}
	return base + off, nil
}

func (d *doc) lineEnd(off int) int { // offset of the line ending after off
	i := bytes.IndexByte(d.data[off:], '\n')
	if i < 0 {
		return len(d.data)
	}
	if i > 0 && d.data[off+i-1] == '\r' {
		i--
	}
	return off + i
}

// matchClose finds the bracket that closes the flow collection opening at off.
func (d *doc) matchClose(off int) (int, error) {
	depth := 0
	for i := off; i < len(d.data); i++ {
		switch c := d.data[i]; c {
		case '[', '{':
			depth++
		case ']', '}':
			if depth--; depth == 0 {
				return i, nil
			}
		case '"', '\'':
			j, err := d.quoteEnd(i)
			if err != nil {
				return 0, err
			}
			i = j - 1
		case '#':
			if i > 0 && (d.data[i-1] == ' ' || d.data[i-1] == '\t') {
				i = d.lineEnd(i) - 1
			}
		}
	}
	return 0, errors.New("unclosed bracket")
}

// quoteEnd is the offset just after the quoted scalar starting at off (one line only).
func (d *doc) quoteEnd(off int) (int, error) {
	q, end := d.data[off], d.lineEnd(off)
	for i := off + 1; i < end; i++ {
		switch {
		case q == '"' && d.data[i] == '\\':
			i++
		case d.data[i] == q && q == '\'' && i+1 < end && d.data[i+1] == '\'':
			i++
		case d.data[i] == q:
			return i + 1, nil
		}
	}
	return 0, errors.New("quoted value spans several lines")
}

// scalarEnd is the offset just after a scalar's text.
func (d *doc) scalarEnd(n *yaml.Node, off int, flow bool) (int, error) {
	switch {
	case n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0:
		return 0, errors.New("multi-line value")
	case n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle) != 0:
		return d.quoteEnd(off)
	}
	end := d.lineEnd(off)
	for i := off; i < end; i++ {
		c := d.data[i]
		if c == '#' && i > off && (d.data[i-1] == ' ' || d.data[i-1] == '\t') {
			end = i
			break
		}
		if flow && (c == ',' || c == '}' || c == ']') {
			end = i
			break
		}
	}
	for end > off && (d.data[end-1] == ' ' || d.data[end-1] == '\t') {
		end--
	}
	if string(d.data[off:end]) != n.Value {
		return 0, errors.New("multi-line value")
	}
	return end, nil
}

// endOffset is the offset just after a node's text.
func (d *doc) endOffset(n *yaml.Node, flow bool) (int, error) {
	off, err := d.offset(n)
	if err != nil {
		return 0, err
	}
	switch {
	case n.Kind == yaml.ScalarNode:
		return d.scalarEnd(n, off, flow)
	case n.Kind == yaml.AliasNode:
		return 0, errors.New("YAML alias")
	case n.Style&yaml.FlowStyle != 0 || flow:
		i, err := d.matchClose(off)
		return i + 1, err
	}
	end := off
	for i, c := range n.Content {
		if n.Kind == yaml.MappingNode && i%2 == 0 {
			continue // keys end at their colon; the values come after them
		}
		e, err := d.endOffset(c, false)
		if err != nil {
			return 0, err
		}
		end = max(end, e)
	}
	return end, nil
}

type edit struct {
	at, end int
	text    string
}

func (d *doc) apply(e edit) []byte {
	out := append([]byte{}, d.data[:e.at]...)
	out = append(out, e.text...)
	return append(out, d.data[e.end:]...)
}

// replaceScalar keeps a trailing comment in its column when the new value is shorter or a little longer.
func (d *doc) replaceScalar(at, end int, text string) edit {
	le := d.lineEnd(end)
	rest := d.data[end:le]
	pad := len(rest) - len(bytes.TrimLeft(rest, " "))
	if pad >= 2 && bytes.HasPrefix(bytes.TrimLeft(rest, " "), []byte("#")) {
		want := max(1, pad+(end-at)-len(text))
		return edit{at, end + pad, text + strings.Repeat(" ", want)}
	}
	return edit{at, end, text}
}

func isNull(n *yaml.Node) bool { return n.Kind == yaml.ScalarNode && n.Tag == "!!null" }

// flowEntry is "a: {b: text}" for the path [a b].
func flowEntry(path []string, text string) string {
	if len(path) == 1 {
		return path[0] + ": " + text
	}
	return path[0] + ": {" + flowEntry(path[1:], text) + "}"
}

// blockLines are the lines for the path at an indentation, without a final line ending.
func (d *doc) blockLines(path []string, text string, indent int) string {
	var b strings.Builder
	for i, p := range path {
		if i > 0 {
			b.WriteString(d.eol)
		}
		b.WriteString(strings.Repeat(" ", indent+i*d.unit) + p + ":")
		if i == len(path)-1 {
			b.WriteString(" " + text)
		}
	}
	return b.String()
}

// insertAfterLine inserts whole lines after the line that holds offset off.
func (d *doc) insertAfterLine(off int, lines string) edit {
	le := d.lineEnd(off)
	i := bytes.IndexByte(d.data[le:], '\n')
	if i < 0 { // last line without a line ending
		return edit{le, le, d.eol + lines + d.eol}
	}
	return edit{le + i + 1, le + i + 1, lines + d.eol}
}

// plan works out the text change for setting path to text.
func (d *doc) plan(root *yaml.Node, path []string, text string) (edit, error) {
	if root == nil || isNull(root) { // empty file (or comments only): append
		at := len(d.data)
		pre := ""
		if at > 0 && d.data[at-1] != '\n' {
			pre = d.eol
		}
		return edit{at, at, pre + d.blockLines(path, text, 0) + d.eol}, nil
	}
	if root.Kind != yaml.MappingNode {
		return edit{}, errors.New("config.yaml is not a list of settings")
	}
	cur := root
	for i := 0; i < len(path); i++ {
		flow := cur.Style&yaml.FlowStyle != 0
		var key, val *yaml.Node
		for j := 0; j+1 < len(cur.Content); j += 2 {
			if cur.Content[j].Value == path[i] {
				key, val = cur.Content[j], cur.Content[j+1]
			}
		}
		rest := path[i:]
		if key == nil { // missing: add it to this section
			if flow {
				open, err := d.offset(cur)
				if err != nil {
					return edit{}, err
				}
				cl, err := d.matchClose(open)
				if err != nil {
					return edit{}, err
				}
				at := cl
				for at > open+1 && (d.data[at-1] == ' ' || d.data[at-1] == '\t') {
					at--
				}
				sep := ""
				if len(cur.Content) > 0 {
					sep = ", "
				}
				return edit{at, at, sep + flowEntry(rest, text)}, nil
			}
			if cur == root {
				return d.plan(nil, rest, text)
			}
			end, err := d.endOffset(cur, false)
			if err != nil {
				return edit{}, err
			}
			return d.insertAfterLine(end-1, d.blockLines(rest, text, cur.Content[0].Column-1)), nil
		}
		koff, err := d.offset(key)
		if err != nil || !bytes.HasPrefix(d.data[koff:], []byte(key.Value)) {
			return edit{}, errors.New("cannot find " + key.Value + " in the text")
		}
		last := i == len(path)-1
		switch {
		case !last && val.Kind == yaml.MappingNode:
			cur = val
			continue
		case !last && !isNull(val):
			return edit{}, fmt.Errorf("%s is not a section", strings.Join(path[:i+1], "."))
		case isNull(val) && val.Value == "": // "key:" with nothing after it
			colon := bytes.IndexByte(d.data[koff:d.lineEnd(koff)], ':')
			if colon < 0 {
				return edit{}, errors.New("cannot find the colon after " + key.Value)
			}
			at := koff + colon + 1
			if !last && !flow {
				return d.insertAfterLine(at, d.blockLines(path[i+1:], text, key.Column-1+d.unit)), nil
			}
			if !last {
				text = "{" + flowEntry(path[i+1:], text) + "}"
			}
			return edit{at, at, " " + text}, nil
		}
		if !last { // an explicit null (~): becomes a flow mapping
			text = "{" + flowEntry(path[i+1:], text) + "}"
		}
		voff, err := d.offset(val)
		if err != nil {
			return edit{}, err
		}
		if val.Kind == yaml.ScalarNode || val.Style&yaml.FlowStyle != 0 || flow {
			end, err := d.endOffset(val, flow)
			if err != nil {
				return edit{}, err
			}
			if val.Kind == yaml.ScalarNode {
				return d.replaceScalar(voff, end, text), nil
			}
			return edit{voff, end, text}, nil
		}
		// a block list / mapping under the key: the new value goes on the key's line, the old lines go
		end, err := d.endOffset(val, false)
		if err != nil {
			return edit{}, err
		}
		colon := bytes.IndexByte(d.data[koff:d.lineEnd(koff)], ':')
		if colon < 0 {
			return edit{}, errors.New("cannot find the colon after " + key.Value)
		}
		at, keyLineEnd := koff+colon+1, d.lineEnd(koff)
		blockStart := d.lineStart[val.Line-1]
		if keyLineEnd > blockStart {
			return edit{}, errors.New("unexpected layout")
		}
		blockEnd := d.lineEnd(end) // through the block's last line ending
		if i := bytes.IndexByte(d.data[blockEnd:], '\n'); i >= 0 {
			blockEnd += i + 1
		}
		// "key: <text> <comment of the key line>", the lines between, then the block's lines are gone
		head := " " + text
		if c := strings.TrimSpace(string(d.data[at:keyLineEnd])); c != "" {
			head += " " + c
		}
		return edit{at, blockEnd, head + string(d.data[keyLineEnd:blockStart])}, nil
	}
	return edit{}, errors.New("empty setting name")
}

// Edit returns config.yaml's text with the setting changed to v (added when missing), and the previous value
// as written in the file (ok false when the file does not set it).
func Edit(data []byte, s Setting, v any) (out []byte, old string, ok bool, err error) {
	text, err := Render(v)
	if err != nil {
		return nil, "", false, err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, "", false, fmt.Errorf("config.yaml is not valid YAML, fix it by hand first: %w", err)
	}
	var top *yaml.Node
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		top = root.Content[0]
	}
	if n := find(top, s.Path); n != nil {
		old, ok = nodeText(n), true
	}
	d := newDoc(data)
	e, err := d.plan(top, s.Path, text)
	if err != nil {
		return nil, old, ok, fmt.Errorf("cannot change %s safely (%v): edit config.yaml by hand", s.Key, err)
	}
	out = d.apply(e)
	if err := verify(data, out, s, v); err != nil {
		return nil, old, ok, fmt.Errorf("cannot change %s safely (%v): edit config.yaml by hand", s.Key, err)
	}
	return out, old, ok, nil
}

func find(n *yaml.Node, path []string) *yaml.Node {
	for _, p := range path {
		if n == nil || n.Kind != yaml.MappingNode {
			return nil
		}
		var next *yaml.Node
		for j := 0; j+1 < len(n.Content); j += 2 {
			if n.Content[j].Value == p {
				next = n.Content[j+1]
			}
		}
		n = next
	}
	return n
}

func nodeText(n *yaml.Node) string {
	if n.Kind == yaml.ScalarNode {
		if isNull(n) {
			return "null"
		}
		return n.Value
	}
	var list []string
	if n.Decode(&list) == nil {
		r, _ := Render(list)
		return r
	}
	return "(" + strings.ToLower(fmt.Sprint(n.Kind)) + ")"
}

// verify decodes both texts: the setting must now be v, and nothing else may differ.
func verify(before, after []byte, s Setting, v any) error {
	var root yaml.Node
	if err := yaml.Unmarshal(after, &root); err != nil {
		return fmt.Errorf("result is not valid YAML: %w", err)
	}
	var top *yaml.Node
	if len(root.Content) == 1 {
		top = root.Content[0]
	}
	n := find(top, s.Path)
	if n == nil {
		return errors.New("setting missing after the change")
	}
	got := reflect.New(reflect.TypeOf(v))
	if err := n.Decode(got.Interface()); err != nil || !same(got.Elem().Interface(), v) {
		return fmt.Errorf("setting reads back as %v", got.Elem().Interface())
	}
	var a, b map[string]any
	if err := yaml.Unmarshal(before, &a); err != nil {
		return err
	}
	if err := yaml.Unmarshal(after, &b); err != nil {
		return err
	}
	drop(a, s.Path)
	drop(b, s.Path)
	if !reflect.DeepEqual(prune(a), prune(b)) {
		return errors.New("other settings would change")
	}
	return nil
}

func same(a, b any) bool {
	if x, ok := a.([]string); ok {
		y, _ := b.([]string)
		return len(x) == len(y) && (len(x) == 0 || reflect.DeepEqual(x, y))
	}
	return reflect.DeepEqual(a, b)
}

func drop(m map[string]any, path []string) {
	for _, p := range path[:len(path)-1] {
		next, ok := m[p].(map[string]any)
		if !ok {
			return
		}
		m = next
	}
	delete(m, path[len(path)-1])
}

// prune removes empty sections and nulls (both mean "defaults" to the agent).
func prune(v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	out := map[string]any{}
	for k, x := range m {
		x = prune(x)
		if sub, ok := x.(map[string]any); x == nil || (ok && len(sub) == 0) {
			continue
		}
		out[k] = x
	}
	return out
}
