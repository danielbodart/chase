import glob, json, sys
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
files={}
for f in sorted(glob.glob('pb/*.pb')):
    fds=descriptor_pb2.FileDescriptorSet(); fds.ParseFromString(open(f,'rb').read())
    for fd in fds.file: files.setdefault(fd.name, fd)
pool=descriptor_pool.DescriptorPool()
added=set()
def add(name):
    if name in added: return
    fd=files[name]
    for dep in fd.dependency: add(dep)
    pool.Add(fd); added.add(name)
for n in files: add(n)
def cls(full): return message_factory.GetMessageClass(pool.FindMessageTypeByName(full))
MO=cls('google.protobuf.MethodOptions'); SO=cls('google.protobuf.ServiceOptions'); FO=cls('google.protobuf.FieldOptions')
http_ext=pool.FindExtensionByName('google.api.http')
host_ext=pool.FindExtensionByName('google.api.default_host')
fb_ext=pool.FindExtensionByName('google.api.field_behavior')
op_ext=pool.FindExtensionByName('google.longrunning.operation_info')
def rule_list(r):
    out=[]
    for kind in ('get','put','post','delete','patch'):
        if r.HasField(kind): out.append((kind.upper(), getattr(r,kind), r.body))
    if r.HasField('custom'): out.append((r.custom.kind, r.custom.path, r.body))
    for a in r.additional_bindings: out+=rule_list(a)
    return out
methods=[]; fields={}
for name,fd in files.items():
    pkg=fd.package
    def walkmsg(m, prefix):
        full=f"{prefix}.{m.name}"
        fl={}
        for fld in m.field:
            o=FO(); o.ParseFromString(fld.options.SerializeToString())
            fb=[descriptor_pb2.FieldDescriptorProto.Type.Name(fld.type)]
            beh=[pool.FindEnumTypeByName('google.api.FieldBehavior').values_by_number[v].name for v in o.Extensions[fb_ext]] if fb_ext else []
            fl[fld.name]=dict(type=fld.type_name.lstrip('.') or None, behavior=beh, label=fld.label)
        fields[full]=fl
        for n in m.nested_type: walkmsg(n, full)
    for m in fd.message_type: walkmsg(m, pkg)
    for s in fd.service:
        so=SO(); so.ParseFromString(s.options.SerializeToString())
        host=so.Extensions[host_ext]
        for m in s.method:
            mo=MO(); mo.ParseFromString(m.options.SerializeToString())
            rules=rule_list(mo.Extensions[http_ext]) if mo.HasExtension(http_ext) else []
            lro=mo.Extensions[op_ext].response_type if mo.HasExtension(op_ext) else ''
            if lro and '.' not in lro: lro=pkg+'.'+lro
            methods.append(dict(file=name, service=f"{pkg}.{s.name}", method=m.name, grpc=f"/{pkg}.{s.name}/{m.name}",
              host=host, input=m.input_type.lstrip('.'), output=m.output_type.lstrip('.'),
              client_streaming=m.client_streaming, server_streaming=m.server_streaming, http=rules, lro=lro))
json.dump(dict(methods=methods, fields=fields), open('protos.json','w'))
print(len(methods), 'rpcs;', sum(1 for m in methods if m['http']), 'with google.api.http;', len({m['service'] for m in methods}),'services;', len({m['host'] for m in methods}),'hosts')
