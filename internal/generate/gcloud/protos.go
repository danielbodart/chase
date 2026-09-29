package gcloud

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// binding is one of an RPC's google.api.http rules: its HTTP method, or a
// custom rule's kind, and its path.
type binding struct {
	verb, path string
}

// rpc is one method of a gRPC service, as the generator needs it.
type rpc struct {
	file, pkg, service, method string
	name                       string // package.Service.Method: its operation's id
	path                       string // /package.Service/Method: its gRPC path
	host                       string // its service's google.api.default_host
	http                       []binding
	streaming                  bool // the client streams
	comment                    string
}

// protos is the compiled protos: every file protoc put in the descriptor
// set, and every method of the services in the entries (and of the
// mixins, wherever they are).
type protos struct {
	files map[string]*descriptorpb.FileDescriptorProto
	rpcs  []rpc
}

var crossReference = regexp.MustCompile(`\[([^\]]+)\]\[[^\]]*\]`)

// loadProtos reads what protoc compiled: nothing here parses a .proto. The
// options of each service and method arrive as bytes protobuf's own types
// cannot read -- google.api.http and google.api.default_host are extensions
// the descriptor set itself defines -- so they are read again against types
// built from the set, as Python's descriptor pool read them.
func loadProtos(descriptors string, entries map[string]bool) (*protos, error) {
	b, err := os.ReadFile(descriptors)
	if err != nil {
		return nil, err
	}
	fds := &descriptorpb.FileDescriptorSet{}
	if err := proto.Unmarshal(b, fds); err != nil {
		return nil, fmt.Errorf("%s: %w", descriptors, err)
	}
	p := &protos{files: map[string]*descriptorpb.FileDescriptorProto{}}
	for _, fd := range fds.File {
		p.files[fd.GetName()] = fd
	}
	registry, err := protodesc.NewFiles(fds)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", descriptors, err)
	}
	types := dynamicpb.NewTypes(registry)
	message := func(name protoreflect.FullName) (protoreflect.MessageDescriptor, error) {
		d, err := registry.FindDescriptorByName(name)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		md, ok := d.(protoreflect.MessageDescriptor)
		if !ok {
			return nil, fmt.Errorf("%s is not a message", name)
		}
		return md, nil
	}
	methodOptions, err := message("google.protobuf.MethodOptions")
	if err != nil {
		return nil, err
	}
	serviceOptions, err := message("google.protobuf.ServiceOptions")
	if err != nil {
		return nil, err
	}
	http, err := types.FindExtensionByName("google.api.http")
	if err != nil {
		return nil, fmt.Errorf("google.api.http: %w", err)
	}
	defaultHost, err := types.FindExtensionByName("google.api.default_host")
	if err != nil {
		return nil, fmt.Errorf("google.api.default_host: %w", err)
	}
	reread := func(options proto.Message, as protoreflect.MessageDescriptor) (*dynamicpb.Message, error) {
		raw, err := proto.Marshal(options)
		if err != nil {
			return nil, err
		}
		m := dynamicpb.NewMessage(as)
		if err := (proto.UnmarshalOptions{Resolver: types}).Unmarshal(raw, m); err != nil {
			return nil, err
		}
		return m, nil
	}

	names := make([]string, 0, len(p.files))
	for name := range p.files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fd := p.files[name]
		if !entries[name] && !servesMixin(fd) {
			continue
		}
		comments := map[string]string{}
		for _, loc := range fd.GetSourceCodeInfo().GetLocation() {
			comments[fmt.Sprint(loc.GetPath())] = loc.GetLeadingComments()
		}
		for si, s := range fd.GetService() {
			so, err := reread(s.GetOptions(), serviceOptions)
			if err != nil {
				return nil, fmt.Errorf("%s: %s: %w", name, s.GetName(), err)
			}
			host := so.Get(defaultHost.TypeDescriptor()).String()
			service := fd.GetPackage() + "." + s.GetName()
			for mi, m := range s.GetMethod() {
				mo, err := reread(m.GetOptions(), methodOptions)
				if err != nil {
					return nil, fmt.Errorf("%s: %s.%s: %w", name, service, m.GetName(), err)
				}
				var rules []binding
				if mo.Has(http.TypeDescriptor()) {
					rules = bindings(mo.Get(http.TypeDescriptor()).Message())
				}
				comment := comments[fmt.Sprint([]int32{6, int32(si), 2, int32(mi)})]
				p.rpcs = append(p.rpcs, rpc{
					file: name, pkg: fd.GetPackage(), service: service, method: m.GetName(),
					name: service + "." + m.GetName(), path: "/" + service + "/" + m.GetName(),
					host: host, http: rules, streaming: m.GetClientStreaming(),
					comment: crossReference.ReplaceAllString(strings.Join(pyFields(comment), " "), "${1}"),
				})
			}
		}
	}
	return p, nil
}

func servesMixin(fd *descriptorpb.FileDescriptorProto) bool {
	for _, s := range fd.GetService() {
		if mixins[fd.GetPackage()+"."+s.GetName()] {
			return true
		}
	}
	return false
}

// bindings is an HttpRule's method and path, a custom rule's kind and path,
// then its additional bindings', each in turn.
func bindings(rule protoreflect.Message) []binding {
	fields := rule.Descriptor().Fields()
	var out []binding
	for _, k := range []string{"get", "put", "post", "delete", "patch"} {
		if fd := fields.ByName(protoreflect.Name(k)); fd != nil && rule.Has(fd) {
			out = append(out, binding{strings.ToUpper(k), rule.Get(fd).String()})
		}
	}
	if fd := fields.ByName("custom"); fd != nil && rule.Has(fd) {
		custom := rule.Get(fd).Message()
		cf := custom.Descriptor().Fields()
		out = append(out, binding{custom.Get(cf.ByName("kind")).String(), custom.Get(cf.ByName("path")).String()})
	}
	if fd := fields.ByName("additional_bindings"); fd != nil {
		list := rule.Get(fd).List()
		for i := 0; i < list.Len(); i++ {
			out = append(out, bindings(list.Get(i).Message())...)
		}
	}
	return out
}

// closure is the files named and every file they import, but protobuf's
// own, which protoc brings.
func (p *protos) closure(names map[string]bool) map[string]bool {
	out := map[string]bool{}
	var add func(string)
	add = func(name string) {
		if out[name] || strings.HasPrefix(name, "google/protobuf/") {
			return
		}
		out[name] = true
		for _, dep := range p.files[name].GetDependency() {
			add(dep)
		}
	}
	for _, name := range sortedKeys(names) {
		add(name)
	}
	return out
}

// dir is os.path.dirname of a proto's name.
func dir(name string) string {
	i := strings.LastIndexByte(name, '/')
	if i < 0 {
		return ""
	}
	return name[:i]
}
