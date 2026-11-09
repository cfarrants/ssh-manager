"""Server-side helpers for a reversible, two-port SSH handover."""
PORT_HELPERS = r'''
def listen_pairs(value):
    pairs=[]
    for address in re.findall(r'(\S+)\s+\(Stream\)',value):
        match=re.fullmatch(r'(\[[^\]]+\]|[^:]+):(\d+)',address)
        if not match:raise ValueError('Unsupported SSH socket address: '+address)
        host,port=match.groups()
        ipaddress.ip_address(host.strip('[]'))
        pairs.append((host,int(port)))
    if not pairs:raise ValueError('Could not read the SSH socket listening addresses')
    return pairs

def config_documents():
    seen=set();documents=[]
    def visit(path):
        path=os.path.realpath(path)
        if path in seen:return
        seen.add(path)
        if len(seen)>128:raise ValueError('Too many SSH include files for automatic port migration')
        text=open(path).read();documents.append((path,text))
        for line in text.splitlines():
            parts=shlex.split(line,comments=True)
            if not parts:continue
            key=parts[0].lower()
            if key=='listenaddress' and any(re.fullmatch(r'(?:\[[^\]]+\]|[^:]+):\d+',value) for value in parts[1:]):
                raise ValueError('A ListenAddress pins a port; automatic migration requires an address without a port')
            if key=='include':
                for pattern in parts[1:]:
                    if not os.path.isabs(pattern):pattern='/etc/ssh/'+pattern
                    for child in sorted(glob.glob(pattern)):visit(child)
    visit(MAIN)
    return documents

def plan_ports(connection,ssh_service):
    new=p.get('new_port')
    if new is None:return {}
    if isinstance(new,bool) or not isinstance(new,int) or not 1<=new<=65535:raise ValueError('Invalid new SSH port')
    parts=connection.split()
    if len(parts)!=4:raise ValueError('Cannot identify the existing SSH port')
    old=int(parts[3])
    socket_unit=''
    for unit in ('ssh.socket','sshd.socket'):
        if subprocess.run(['systemctl','is-active','--quiet',unit],capture_output=True).returncode==0:
            socket_unit=unit;break
    listeners=[]
    if socket_unit:
        killmode=command(['systemctl','show',ssh_service,'--property=KillMode','--value'])
        if killmode!='process':raise ValueError('Socket port migration requires SSH KillMode=process so active sessions survive')
        listeners=listen_pairs(command(['systemctl','show',socket_unit,'--property=Listen','--value']))
        if {port for _,port in listeners}!={old}:raise ValueError('Multiple existing socket ports require manual migration')
    else:
        ports={int(value) for value in effective(p['bootstrap_user'],connection).get('port','22').split()}
        if ports!={old}:raise ValueError('Custom or multiple existing SSH ports require manual migration')
    if new!=old:
        for family,address in ((socket.AF_INET,('0.0.0.0',new)),(socket.AF_INET6,('::',new))):
            if family==socket.AF_INET6 and not socket.has_ipv6:continue
            try:
                with socket.socket(family,socket.SOCK_STREAM) as probe:probe.bind(address)
            except OSError as error:
                if family==socket.AF_INET6 and error.errno in (97,99):continue
                raise ValueError('New SSH port is unavailable: '+str(new)) from error
    return dict(new_port=new,old_port=old,socket_unit=socket_unit,socket_listeners=listeners,documents=config_documents())

def backup_ports(state,details):
    if not details:return
    state.update({key:value for key,value in details.items() if key!='documents'})
    state['port_files']=[]
    marker='# ssh-manager-port-'+os.path.basename(state['directory'])+': '
    for path,text in details['documents']:
        changes=[]
        for line in text.splitlines(keepends=True):
            if re.match(r'^\s*Port(?:\s+|=)\d',line,re.IGNORECASE):
                changes.append(dict(original=line,managed=marker+line))
        if not changes:continue
        backup=state['directory']+'/port-config-'+str(len(state['port_files']))+'.before'
        write(backup,text)
        state['port_files'].append(dict(path=path,before=backup,mode=os.stat(path).st_mode&0o777,digest=hashlib.sha256(text.encode()).hexdigest(),changes=changes))
    if state['socket_unit']:
        directory='/etc/systemd/system/'+state['socket_unit']+'.d'
        state['socket_override']=directory+'/zz-ssh-manager-'+os.path.basename(state['directory'])+'.conf'

def check_port_sources(state):
    for item in state.get('port_files',[]):
        if hashlib.sha256(open(item['path']).read().encode()).hexdigest()!=item['digest']:
            raise ValueError('An SSH include changed during setup; original SSH access retained')

def mark_original_ports(state):
    for item in state.get('port_files',[]):
        content=open(item['path']).read()
        for change in item['changes']:content=content.replace(change['original'],change['managed'],1)
        write(item['path'],content,item['mode'])

def managed_port_policy(state,final=False):
    ports=[state['new_port']] if final else list(dict.fromkeys((state['old_port'],state['new_port'])))
    return state['base_policy']+''.join('Port '+str(port)+'\n' for port in ports)

def activate_ports(state,final=False):
    if not state.get('socket_unit'):
        command(['systemctl','reload',state['service']])
        return
    pairs=[]
    for host,old in state['socket_listeners']:
        if not final:pairs.append((host,old))
        pairs.append((host,state['new_port']))
    pairs=list(dict.fromkeys(pairs))
    path=state['socket_override'];os.makedirs(os.path.dirname(path),mode=0o755,exist_ok=True)
    write(path,'[Socket]\nListenStream=\n'+''.join('ListenStream='+host+':'+str(port)+'\n' for host,port in pairs),0o644)
    command(['systemctl','daemon-reload'])
    actual=set(listen_pairs(command(['systemctl','show',state['socket_unit'],'--property=Listen','--value'])))
    if actual!=set(pairs):raise ValueError('Another socket override conflicts with the requested ports')
    command(['systemctl','restart',state['socket_unit'],state['service']])

def finish_port(state):
    if not state.get('new_port') or state['phase']!='applied' or not state.get('new_port_verified'):
        raise ValueError('A fresh new-port login must succeed before retiring the old port')
    if p.get('_actual_user')!=state['new_user'] or int(p['_connection'].split()[3])!=state['new_port']:
        raise ValueError('Port finalization must run through the verified new port')
    try:
        write(state['policy'],managed_port_policy(state,True))
        state['phase']='port-finalized';save(state)
        check_policy(state)
        activate_ports(state,True)
        return dict(phase='port-finalized',port=state['new_port'])
    except Exception:
        rollback(state);raise
'''
