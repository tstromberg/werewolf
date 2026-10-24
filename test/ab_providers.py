"""Disposable provider lifecycle adapters for the A/B regression runner."""
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import socket
import subprocess
import tarfile
import time


def port():
    with socket.socket() as connection:
        connection.bind(('127.0.0.1', 0))
        return connection.getsockname()[1]


class Provider:
    def __init__(self, kind, fixture, work, howl):
        self.kind, self.fixture, self.work, self.howl = kind, fixture, work, howl
        self.name = 'wwab-' + os.urandom(6).hex()
        self.env = dict(os.environ)
        self.process = None
        self.remote = None
        self.remote_dir = None
        self.cloud_created = False
        self.lima_created = False
        self.proxy = None
        self.image = None
        self.own_group = False
        self.address, self.ssh_port = '127.0.0.1', 22
        self.log = work / 'console.raw.log'
        self.config = work / 'config'
        self.config.mkdir()
        (self.config / 'hostname').write_text(self.name + '\n')
        (self.config / 'authorized_keys').write_text(Path(fixture['ssh_key'] + '.pub').read_text())
        if kind == 'bhyve':
            self.bhyve_howl = self.env.get('BHYVE_LAUNCH') == 'howl'
            if self.env.get('BHYVE_LAUNCH', 'direct') not in ('direct', 'howl'):
                raise RuntimeError('BHYVE_LAUNCH must be direct or howl')
            if self.bhyve_howl and (fixture['mode'] != 'plain' or not self.env.get('BHYVE_BRIDGE')):
                raise RuntimeError('BHYVE_LAUNCH=howl requires plain mode and BHYVE_BRIDGE')
            self.bhyve_binary = self.env.get('BHYVE_BINARY', 'bhyve')
            if self.bhyve_binary != 'bhyve' and not self.bhyve_binary.startswith('/'):
                raise RuntimeError('BHYVE_BINARY must be an absolute remote path')
            self.bhyve_arm64_firmware = self.env.get(
                'BHYVE_ARM64_FIRMWARE', '/usr/local/share/u-boot/u-boot-bhyve-arm64/u-boot.bin')
            if (not self.bhyve_arm64_firmware.startswith('/') or
                    any(c in self.bhyve_arm64_firmware for c in ',\n\r')):
                raise RuntimeError('BHYVE_ARM64_FIRMWARE must be an absolute remote path without commas or newlines')
            self.bhyve_tap = self.env.get('BHYVE_TAP')
            if self.bhyve_tap or self.bhyve_howl:
                if self.bhyve_howl and self.bhyve_tap:
                    raise RuntimeError('howl owns its TAP; omit BHYVE_TAP with BHYVE_LAUNCH=howl')
                if self.bhyve_tap and not re.fullmatch(r'tap[0-9]+', self.bhyve_tap):
                    raise RuntimeError('BHYVE_TAP must name an existing tap interface')
                ip = ipaddress.IPv4Interface(self.env['BHYVE_TEST_IP'])
                gateway = ipaddress.IPv4Address(self.env['BHYVE_TEST_GW'])
                self.address = str(ip.ip)
                network = f'werewolf.ip={ip} werewolf.gw={gateway} werewolf.dns={gateway}\n'
            else:
                network = 'werewolf.ip=10.0.2.15/24 werewolf.gw=10.0.2.2 werewolf.dns=10.0.2.3\n'
            (self.config / 'network').write_text(network)
        self.write_config()
        self.env.update(WEREWOLF_IPE_KERNEL=fixture['kernel'], WEREWOLF_IPE_KEY=fixture['key'],
                        WEREWOLF_IPE_CRT=fixture['cert'], IPE_UPDATES=fixture['channel'],
                        IMAGE_SERIAL=fixture['initial_serial'])
        if fixture['mode'] == 'secure':
            self.env.update(WEREWOLF_BOOT_KEY=fixture.get('boot_key', fixture['key']), WEREWOLF_BOOT_CRT=fixture.get('boot_cert', fixture['cert']))
        else:
            self.env.pop('WEREWOLF_BOOT_KEY', None)
            self.env.pop('WEREWOLF_BOOT_CRT', None)

    def write_config(self):
        with tarfile.open(self.work / 'config.tar', 'w', format=tarfile.USTAR_FORMAT) as archive:
            for path in self.config.iterdir():
                data = path.read_bytes()
                entry = tarfile.TarInfo(path.name)
                entry.size, entry.mode = len(data), 0o644
                archive.addfile(entry, io.BytesIO(data))

    def run(self, args, check=True, timeout=900, input=None):
        args = [str(arg) for arg in args]
        result = subprocess.run(args, env=self.env, capture_output=True, text=True,
                                timeout=timeout, input=input)
        with (self.work / 'host.log').open('a') as output:
            output.write(shlex.join(args) + '\n' + result.stderr + '\n')
        if check and result.returncode:
            raise RuntimeError(shlex.join(args[:4]) + ': ' + (result.stderr + result.stdout)[-3000:])
        return result

    def enroll(self, directory):
        lima_home = self.env.pop('LIMA_HOME', None)
        if 'LIMA_HOME' in os.environ:
            self.env['LIMA_HOME'] = os.environ['LIMA_HOME']
        try:
            if self.fixture.get('firmware'):
                shutil.copytree(self.fixture['firmware'], directory)
            else:
                self.run(['sh', 'tools/enroll-boot', self.fixture['arch'], self.fixture.get('boot_cert', self.fixture['cert']), str(directory)])
        finally:
            self.env.pop('LIMA_HOME', None)
            if lima_home is not None:
                self.env['LIMA_HOME'] = lima_home

    def start(self):
        if self.kind == 'qemu':
            self.start_qemu()
        elif self.kind in ['lima-qemu', 'lima-vz']:
            self.start_lima()
        elif self.kind in ['aws', 'gcp', 'azure']:
            self.start_cloud()
        elif self.kind in ['bhyve', 'firecracker']:
            self.start_remote()
        elif self.kind == 'proxmox':
            self.start_proxmox()
        else:
            raise RuntimeError('provider adapter not available: ' + self.kind)

    def start_qemu(self):
        arch = self.fixture['arch']
        self.ssh_port = port()
        disk = self.work / 'disk.qcow2'
        shutil.copyfile(self.fixture['disk'], disk)
        accel = 'hvf' if platform.system() == 'Darwin' else (
            'kvm' if os.access('/dev/kvm', os.R_OK | os.W_OK) else 'tcg')
        if arch != ('aarch64' if platform.machine() in ['aarch64', 'arm64'] else 'x86_64'):
            accel = 'tcg'
        args = ['qemu-system-' + arch, '-M', 'virt' if arch == 'aarch64' else 'q35,smm=on',
                '-accel', accel, '-cpu', 'max' if accel == 'tcg' else 'host', '-smp', '2',
                '-m', '3072', '-nographic', '-drive', f'file={disk},format=qcow2,if=virtio',
                '-drive', f'file={self.work}/config.tar,format=raw,if=virtio,readonly=on',
                '-netdev', f'user,id=n0,hostfwd=tcp:127.0.0.1:{self.ssh_port}-:22',
                '-device', 'virtio-net-pci,netdev=n0,romfile=',
                '-device', 'virtio-rng-pci']
        firmware = self.work / 'enrolled'
        if self.fixture['mode'] == 'plain':
            self.env['ENROLL_TEST_SETUP'] = '1'
        self.enroll(firmware)
        if self.fixture['mode'] == 'plain':
            shutil.copyfile(firmware / 'setup.fd', firmware / 'vars.fd')
        frozen = 'readonly=on,' if arch == 'aarch64' else ''
        args += ['-drive', f'if=pflash,format=raw,unit=0,readonly=on,file={firmware}/code.fd',
                 '-drive', f'if=pflash,format=raw,unit=1,{frozen}file={firmware}/vars.fd']
        if arch == 'x86_64':
            args += ['-global', 'driver=cfi.pflash01,property=secure,value=on']
        if self.fixture.get('tpm_socket'):
            ppi = ',ppi=off' if accel == 'hvf' else ''
            args += ['-chardev', 'socket,id=tpmsock,path=' + self.fixture['tpm_socket'],
                     '-tpmdev', 'emulator,id=tpm0,chardev=tpmsock',
                     '-device', ('tpm-tis' if arch == 'x86_64' else 'tpm-tis-device') + ',tpmdev=tpm0' + ppi]
        self.qemu_args = args
        self.vars_path = firmware / 'vars.fd'
        self.vars_digest = hashlib.sha256(self.vars_path.read_bytes()).digest()
        with self.log.open('wb') as output:
            self.process = subprocess.Popen(args, env=self.env, stdout=output,
                                            stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)

    def start_lima(self):
        if platform.system() != 'Darwin':
            raise RuntimeError('Lima provider tests require macOS')
        if self.fixture['arch'] != 'aarch64' or platform.machine() != 'arm64':
            raise RuntimeError('this Lima adapter currently requires an arm64 Mac')
        self.env['LIMA_HOME'] = str(self.work / 'lima')
        backend = self.kind.removeprefix('lima-')
        config_disk = self.name + '-config'
        self.run(['limactl', 'disk', 'import', config_disk, str(self.work / 'config.tar')])
        self.lima_created = True
        config = {'vmType': backend, 'plain': True, 'arch': self.fixture['arch'],
                  'cpus': 2, 'memory': '3GiB', 'mounts': [],
                  'containerd': {'system': False, 'user': False},
                  'images': [{'location': self.fixture['disk'], 'arch': self.fixture['arch']}],
                  'additionalDisks': [{'name': config_disk, 'readOnly': True}]}
        if backend == 'qemu' and self.fixture['mode'] == 'secure':
            firmware = self.work / 'enrolled'
            self.enroll(firmware)
            config['firmware'] = {'images': [{'location': str(firmware / 'code.fd'),
                                              'arch': self.fixture['arch'], 'vmType': 'qemu'}]}
            drive = f'if=pflash,format=raw,unit=1,readonly=on,file={firmware}/vars.fd'
            self.env['QEMU_SYSTEM_AARCH64'] = 'qemu-system-aarch64 -drive ' + shlex.quote(drive)
            self.vars_path = firmware / 'vars.fd'
            self.vars_digest = hashlib.sha256(self.vars_path.read_bytes()).digest()
        template = self.work / 'lima.yaml'
        template.write_text(json.dumps(config))
        self.run(['limactl', 'create', '--tty=false', '--name=' + self.name, str(template)])
        with (self.work / 'lima-start.log').open('wb') as output:
            self.process = subprocess.Popen(['limactl', 'start', '--tty=false', self.name],
                                            env=self.env, stdout=output, stderr=subprocess.STDOUT)
        until = time.monotonic() + 45
        while time.monotonic() < until:
            info = json.loads(self.run(['limactl', 'list', self.name, '--json']).stdout)
            self.ssh_port = info.get('sshLocalPort', 0)
            if self.ssh_port:
                return
            time.sleep(1)
        raise RuntimeError('Lima did not assign its SSH forwarding port')

    def start_cloud(self):
        if self.kind == 'gcp':
            self.env['CLOUDSDK_COMPUTE_ZONE'] = self.env.get('GCP_ZONE', 'us-central1-b')
            if self.env.get('GCP_PROJECT'):
                self.env['CLOUDSDK_CORE_PROJECT'] = self.env['GCP_PROJECT']
        if self.kind == 'azure' and not self.env.get('AZURE_DEFAULTS_GROUP'):
            self.env['AZURE_DEFAULTS_GROUP'] = self.name
            self.own_group = True
            self.run(['az', 'group', 'create', '-n', self.name, '-l', 'westus2', '-o', 'none'])
        # This adapter exercises the legacy cloud slot path, without local
        # exact-pair TPM enrollment. Protected-default CLI tests are separate.
        args = [self.howl, 'create', self.name, '--disable=secureboot,tpm,ipe',
                '--with', self.fixture['form'],
                '--on', self.kind, '--arch', self.fixture['arch'], '--build',
                '--config', str(self.config), '--allow-from', 'me']
        size = self.env.get('CLOUD_SIZE')
        if not size and self.kind == 'aws':
            size = 't4g.medium' if self.fixture['arch'] == 'aarch64' else 't3.medium'
        if not size and self.kind == 'azure' and self.fixture['arch'] == 'x86_64':
            size = 'Standard_D2s_v5'
        if size:
            args += ['--size', size]
        self.cloud_created = True
        result = self.run(args, check=False, timeout=2400)
        match = re.search(r'(?:howl|werewolf): image ([a-z0-9-]+): making it ', result.stderr)
        if match:
            self.image = match[1]
        if result.returncode:
            raise RuntimeError('provider create failed; see host.log and console.raw.log')
        self.address = result.stdout.strip().split('\t')[1]

    def remote_command(self, args, check=True, timeout=900):
        return self.run(['ssh', '-o', 'BatchMode=yes', self.remote, 'sh', '-s'],
                        input=shlex.join(args) + '\n', check=check, timeout=timeout)

    def start_proxmox(self):
        if self.fixture['mode'] != 'plain':
            raise RuntimeError('Proxmox enrollment is not implemented; select AB_MODE=plain')
        self.remote = self.env.get('PROXMOX_HOST')
        storage = self.env.get('PROXMOX_STORAGE', 'local-lvm')
        bridge = self.env.get('PROXMOX_BRIDGE', 'vmbr0')
        if not self.remote or not re.fullmatch(r'[a-zA-Z0-9_.@:-]+', self.remote):
            raise RuntimeError('PROXMOX_HOST must name an SSH node with qm privileges')
        for field in [storage, bridge]:
            if not re.fullmatch(r'[a-zA-Z0-9_.-]+', field):
                raise RuntimeError('invalid Proxmox storage or bridge')
        directory = self.remote_command(['mktemp', '-d', '/tmp/ww-ab.XXXXXXXX']).stdout.strip()
        if not re.fullmatch(r'/tmp/ww-ab\.[A-Za-z0-9]+', directory):
            raise RuntimeError('invalid remote test directory')
        self.remote_dir = directory
        self.run(['scp', '-q', self.fixture['disk'], self.remote + ':' + self.remote_dir + '/disk.qcow2'])
        self.run(['scp', '-q', str(self.work / 'config.tar'), self.remote + ':' + self.remote_dir + '/config.tar'])
        self.vmid = self.remote_command(['pvesh', 'get', '/cluster/nextid']).stdout.strip().strip('"')
        if not self.vmid.isdigit():
            raise RuntimeError('invalid Proxmox VMID')
        self.remote_command(['qm', 'create', self.vmid, '--name', self.name,
            '--description', 'werewolf-ab: ' + self.name, '--tags', 'werewolf-ab',
            '--machine', 'q35', '--bios', 'ovmf', '--efidisk0', storage + ':1,efitype=4m,pre-enrolled-keys=0',
            '--cpu', 'host', '--cores', '2', '--memory', '3072', '--ostype', 'l26',
            '--virtio0', storage + ':0,import-from=' + self.remote_dir + '/disk.qcow2',
            '--virtio1', storage + ':0,import-from=' + self.remote_dir + '/config.tar,format=raw,ro=1',
            '--boot', 'order=virtio0', '--net0', 'virtio,bridge=' + bridge,
            '--rng0', 'source=/dev/urandom', '--args',
            '-chardev file,id=werewolf,path=' + self.remote_dir + '/console.log -device isa-serial,chardev=werewolf'])
        self.proxmox_created = True
        self.remote_command(['qm', 'start', self.vmid])
        until = time.monotonic() + 180
        while time.monotonic() < until:
            text = self.remote_command(['cat', self.remote_dir + '/console.log'], check=False).stdout
            match = re.search(r'"event":"bound"[^\n]*"addr":"([0-9.]+)/[0-9]+"', text)
            if match:
                self.address = match[1].split('/')[0]
                self.proxy = shlex.join(['ssh', '-o', 'BatchMode=yes', '-W', self.address + ':22', self.remote])
                return
            time.sleep(3)
        raise RuntimeError('Proxmox guest did not report its DHCP address')

    def start_remote(self):
        if self.kind == 'bhyve' and self.fixture['arch'] == 'aarch64' and self.fixture['mode'] == 'secure':
            raise RuntimeError('arm64 bhyve Secure Boot enrollment is unsupported')
        if self.kind == 'bhyve' and self.fixture['mode'] == 'secure' and not self.env.get('SECUREBOOT_DIR'):
            raise RuntimeError('signed bhyve tests require SECUREBOOT_DIR with bhyve code.fd and vars.fd')
        self.remote = self.env.get('BHYVE_HOST', 'bilbo') if self.kind == 'bhyve' else self.env.get('FIRECRACKER_HOST', 'galadriel')
        if not re.fullmatch(r'[a-zA-Z0-9_.@:-]+', self.remote):
            raise RuntimeError('invalid remote test host')
        directory = self.remote_command(['mktemp', '-d', '/tmp/ww-ab.XXXXXXXX']).stdout.strip()
        if not re.fullmatch(r'/tmp/ww-ab\.[A-Za-z0-9]+', directory):
            raise RuntimeError('invalid remote private directory')
        self.remote_dir = directory
        if self.kind == 'bhyve':
            # Convert on the builder: the FreeBSD host needs only base zstd,
            # not a QEMU installation to test another hypervisor.
            raw = self.work / 'disk.img'
            packed = self.work / 'disk.img.zst'
            self.run(['qemu-img', 'convert', '-f', 'qcow2', '-O', 'raw', self.fixture['disk'], raw])
            self.run(['zstd', '-q', str(raw), '-o', str(packed)])
            self.run(['scp', '-q', str(packed), self.remote + ':' + self.remote_dir + '/disk.img.zst'])
            self.remote_command(['zstd', '-d', '-q', self.remote_dir + '/disk.img.zst',
                                 '-o', self.remote_dir + '/disk.img'])
        else:
            self.run(['scp', '-q', self.fixture['disk'], self.remote + ':' + self.remote_dir + '/disk.qcow2'])
            self.remote_command(['qemu-img', 'convert', '-f', 'qcow2', '-O', 'raw',
                                 self.remote_dir + '/disk.qcow2', self.remote_dir + '/disk.img'])
        if self.kind == 'bhyve':
            self.ssh_port = 20000 + int.from_bytes(hashlib.sha256(self.name.encode()).digest()[:2], 'big') % 400 * 100
            arch = self.fixture['arch']
            binary = Path('build') / arch / 'tools/howl-freebsd'
            binary = binary.resolve()
            self.run(['make', str(binary.relative_to(Path.cwd()))])
            self.run(['scp', '-q', str(self.work / 'config.tar'), str(binary), self.remote + ':' + self.remote_dir + '/'])
            if self.bhyve_howl:
                self.start_bhyve_howl()
                return
            args = [self.bhyve_binary]
            if arch == 'x86_64':
                args += ['-H', '-w', '-u']
            args += ['-c', '2', '-m', '3072M', '-s', '0,hostbridge']
            if arch == 'x86_64':
                args += ['-s', '1,lpc']
            network = (f'2,virtio-net,{self.bhyve_tap}' if self.bhyve_tap else
                       f'2,virtio-net,slirp,open,hostfwd=tcp:127.0.0.1:{self.ssh_port}-:22')
            args += ['-s', network,
                    '-s', '3,virtio-blk,' + self.remote_dir + '/disk.img',
                    '-s', '4,virtio-blk,' + self.remote_dir + '/config.tar,ro',
                    '-s', '5,virtio-rnd']
            if arch == 'aarch64':
                if self.fixture['mode'] == 'secure':
                    raise RuntimeError('arm64 bhyve Secure Boot enrollment is unsupported')
                args += ['-o', 'console=stdio', '-o',
                         'bootrom=' + self.bhyve_arm64_firmware]
            else:
                args += ['-l', 'com1,stdio']
            if self.fixture['mode'] == 'secure':
                firmware = self.work / 'enrolled'
                self.enroll(firmware)
                self.run(['scp', '-q', str(firmware / 'code.fd'), str(firmware / 'vars.fd'), self.remote + ':' + self.remote_dir + '/'])
                args += ['-l', f'bootrom,{self.remote_dir}/code.fd,{self.remote_dir}/vars.fd']
            elif arch == 'x86_64':
                args += ['-l', 'bootrom,/usr/local/share/uefi-firmware/BHYVE_UEFI.fd']
            args += [self.name]
            launch = ['doas', '-n', self.remote_dir + '/howl-freebsd', '_bhyve', self.name,
                      self.remote_dir + '/config.tar', *args]
            target = self.address + ':22' if self.bhyve_tap else '127.0.0.1:' + str(self.ssh_port)
            self.proxy = shlex.join(['ssh', '-o', 'BatchMode=yes', '-W', target, self.remote])
            self.ssh_port = 22
        else:
            h = hashlib.sha256(Path(self.remote_dir).name.encode()).digest()
            octet, subnet = h[0], (h[1] & 0x3f) << 2
            self.tap = 'fc' + h[2:6].hex()
            self.address = f'172.16.{octet}.{subnet + 2}'
            host_ip = f'172.16.{octet}.{subnet + 1}'
            (self.config / 'network').write_text(f'werewolf.ip={self.address}/30 werewolf.gw={host_ip} werewolf.dns=1.1.1.1\n')
            self.write_config()
            image = self.remote_dir + '/disk.img@@1048576'
            entry = self.remote_command(['mtype', '-i', image, '::/loader/entries/werewolf-a.conf']).stdout
            if re.search(r'^(?:efi|uki|uki-url)(?:\s|$)', entry, re.M):
                raise RuntimeError('Firecracker cannot boot an EFI release')
            patched = self.work / 'entry.conf'
            patched.write_text(re.sub(r'^(options .*)$', r'\1 reboot=k', entry, flags=re.M))
            self.run(['scp', '-q', str(patched), self.remote + ':' + self.remote_dir + '/entry.conf'])
            self.remote_command(['mcopy', '-o', '-i', image, self.remote_dir + '/entry.conf', '::/loader/entries/werewolf-a.conf'])
            binary = Path('build/x86_64/tools/howl-linux').resolve()
            self.run(['make', str(binary.relative_to(Path.cwd()))])
            self.run(['scp', '-q', str(self.work / 'config.tar'), str(binary), self.remote + ':' + self.remote_dir + '/'])
            self.remote_command(['doas', '-n', 'ip', 'tuntap', 'add', 'dev', self.tap, 'mode', 'tap'])
            self.tap_created = True
            self.remote_command(['doas', '-n', 'ip', 'addr', 'add', host_ip + '/30', 'dev', self.tap])
            self.remote_command(['doas', '-n', 'ip', 'link', 'set', self.tap, 'up'])
            launch = ['doas', '-n', self.remote_dir + '/howl-linux', '_firecracker', self.remote_dir]
            self.proxy = shlex.join(['ssh', '-o', 'BatchMode=yes', '-W', self.address + ':22', self.remote])
        script = 'nohup ' + shlex.join(launch) + ' >' + shlex.quote(self.remote_dir + '/console.log') + ' 2>&1 </dev/null &\necho $!\n'
        result = self.run(['ssh', '-o', 'BatchMode=yes', self.remote, 'sh', '-s'], input=script)
        self.remote_pid = result.stdout.strip()

    def remote_howl(self, *args):
        overrides = ['BHYVE_BINARY=' + self.bhyve_binary] if self.bhyve_binary != 'bhyve' else []
        command = ['env', *overrides, 'BHYVE_ARM64_FIRMWARE=' + self.bhyve_arm64_firmware,
                   './howl-freebsd', *args]
        return self.remote_command(['sh', '-c', 'cd ' + shlex.quote(self.remote_dir) +
                                    ' && ' + shlex.join(command)])

    def start_bhyve_howl(self):
        # Seed the existing-machine record to boot the immutable signed fixture
        # through normal create, without rebuilding it on the FreeBSD host.
        machine = 'build/machines/' + self.name
        assets = self.work / 'launch.tar'
        with tarfile.open(assets, 'w') as archive:
            archive.add('forms', arcname='forms')
            archive.add(self.config, arcname='test-config')
            for path, data in [(machine + '/form', b'playground\n'),
                               (machine + '/engine', b'bhyve\n')]:
                entry = tarfile.TarInfo(path)
                entry.size, entry.mode = len(data), 0o600
                archive.addfile(entry, io.BytesIO(data))
        self.run(['scp', '-q', assets, self.remote + ':' + self.remote_dir + '/launch.tar'])
        self.remote_command(['tar', '-xf', self.remote_dir + '/launch.tar', '-C', self.remote_dir])
        self.remote_command(['mv', self.remote_dir + '/disk.img', self.remote_dir + '/' + machine + '/disk.img'])
        self.bhyve_machine = self.remote_dir + '/' + machine
        self.remote_howl('create', self.name, '--with', 'playground', '--build', '--on', 'bhyve',
                         '--disable=secureboot,tpm,ipe', '--network', 'tap',
                         '--bridge', self.env['BHYVE_BRIDGE'], '--config', 'test-config')
        self.proxy = shlex.join(['ssh', '-o', 'BatchMode=yes', '-W', self.address + ':22', self.remote])
        self.ssh_port = 22

    def ssh(self, command, check=True, timeout=120):
        return self.run(self.ssh_args(command), check=check, timeout=timeout)

    def ssh_args(self, command):
        args = ['ssh', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                '-o', 'ConnectTimeout=5', '-o', 'StrictHostKeyChecking=accept-new',
                '-o', 'UserKnownHostsFile=' + str(self.work / 'known_hosts'),
                '-i', self.fixture['ssh_key'], '-p', str(self.ssh_port)]
        if self.proxy:
            args += ['-o', 'ProxyCommand=' + self.proxy]
        return [*args, 'root@' + self.address, command]

    def reboot(self, command='/usr/bin/reboot'):
        # A Lima forwarder may hold the SSH connection after the guest exits.
        # The runner must still prove a fresh, authenticated boot afterward.
        try:
            self.ssh(command, check=False, timeout=15)
        except subprocess.TimeoutExpired:
            with (self.work / 'host.log').open('a') as log:
                log.write('SSH restart connection remained open; awaiting fresh boot evidence\n')

    def console(self):
        if self.kind in ['aws', 'gcp', 'azure'] and self.cloud_created:
            result = self.run([self.howl, 'console', self.name, '--on', self.kind], check=False)
            self.log.write_text(result.stdout)
        elif self.kind.startswith('lima-') and self.lima_created:
            text = b''.join(p.read_bytes() for p in (Path(self.env['LIMA_HOME']) / self.name).glob('serial*.log'))
            self.log.write_bytes(text)
        elif self.remote_dir:
            args = ['cat', getattr(self, 'bhyve_machine', self.remote_dir) + '/console.log']
            if self.kind != 'proxmox':
                args = ['doas', '-n', *args]
            result = self.remote_command(args, check=False)
            self.log.write_text(result.stdout)
        return self.log.read_text(errors='replace') if self.log.exists() else ''

    def stop(self):
        errors = []

        def attempt(action):
            try:
                action()
            except Exception as error:
                errors.append(str(error))

        attempt(self.console)
        if self.process is not None and self.kind == 'qemu':
            attempt(self.stop_process)
        if self.lima_created:
            attempt(lambda: self.run(['limactl', 'delete', '--force', self.name]))
            attempt(lambda: self.run(['limactl', 'disk', 'delete', self.name + '-config']))
            if self.process is not None:
                attempt(self.stop_process)
        if self.cloud_created:
            attempt(lambda: self.run([self.howl, 'delete', self.name, '--on', self.kind]))
        if self.own_group:
            attempt(lambda: self.run(['az', 'group', 'delete', '-n', self.name, '--yes', '--no-wait']))
        elif self.cloud_created and self.image:
            attempt(self.delete_image)
        if self.remote_dir:
            if self.kind == 'proxmox' and getattr(self, 'proxmox_created', False):
                attempt(self.delete_proxmox)
            if self.kind == 'firecracker':
                attempt(lambda: self.remote_command(['doas', '-n', 'rm', '-f', self.remote_dir + '/config.tar']))
                def kill_child():
                    child = self.remote_command(['doas', '-n', 'cat', self.remote_dir + '/firecracker.pid'], check=False).stdout.strip()
                    if child.isdigit():
                        self.remote_command(['doas', '-n', 'kill', child], check=False)
                attempt(kill_child)
            if self.kind == 'bhyve':
                if getattr(self, 'bhyve_machine', None):
                    attempt(lambda: self.remote_howl('delete', self.name, '--on', 'bhyve'))
                    if errors:
                        raise RuntimeError('howl cleanup failed; retained ' + self.remote_dir + ': ' + '; '.join(errors))
                else:
                    attempt(lambda: self.remote_command(['doas', '-n', 'bhyvectl', '--vm=' + self.name, '--destroy'], check=False))
            if getattr(self, 'remote_pid', '').isdigit():
                attempt(lambda: self.remote_command(['doas', '-n', 'kill', self.remote_pid], check=False))
            if self.kind == 'firecracker' and getattr(self, 'tap_created', False):
                attempt(lambda: self.remote_command(['doas', '-n', 'ip', 'link', 'delete', self.tap]))
            delete = ['rm', '-rf', self.remote_dir]
            if self.kind != 'proxmox':
                delete = ['doas', '-n', *delete]
            attempt(lambda: self.remote_command(delete))
        if getattr(self, 'vars_path', None) and self.fixture['arch'] == 'aarch64' and self.kind != 'bhyve':
            if hashlib.sha256(self.vars_path.read_bytes()).digest() != self.vars_digest:
                errors.append('immutable firmware enrollment changed')
        if errors:
            (self.work / 'cleanup-errors.log').write_text('\n'.join(errors))
            raise RuntimeError('cleanup failed: ' + '; '.join(errors))

    def stop_process(self):
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=10)

    def delete_proxmox(self):
        config = self.remote_command(['qm', 'config', self.vmid]).stdout
        if 'name: ' + self.name + '\n' not in config:
            raise RuntimeError('refusing to remove a Proxmox VM with a different owner/name')
        self.remote_command(['qm', 'stop', self.vmid], check=False)
        self.remote_command(['qm', 'destroy', self.vmid, '--purge', '1', '--destroy-unreferenced-disks', '1'])

    def delete_image(self):
        if self.kind == 'gcp':
            self.run(['gcloud', '--quiet', 'compute', 'images', 'delete', self.image])
        elif self.kind == 'aws':
            records = json.loads(self.run(['aws', 'ec2', 'describe-images', '--owners', 'self',
                '--filters', 'Name=name,Values=' + self.image, '--output', 'json']).stdout)['Images']
            for record in records:
                self.run(['aws', 'ec2', 'deregister-image', '--image-id', record['ImageId']])
                for mapping in record.get('BlockDeviceMappings', []):
                    snapshot = mapping.get('Ebs', {}).get('SnapshotId')
                    if snapshot:
                        self.run(['aws', 'ec2', 'delete-snapshot', '--snapshot-id', snapshot])
        elif self.kind == 'azure':
            group, gallery = self.env['AZURE_DEFAULTS_GROUP'], self.image.replace('-', '_')
            self.run(['az', 'sig', 'image-version', 'delete', '-g', group, '--gallery-name', gallery,
                '--gallery-image-definition', 'boot', '--gallery-image-version', '1.0.0', '-o', 'none'])
            self.run(['az', 'sig', 'image-definition', 'delete', '-g', group, '--gallery-name', gallery,
                '--gallery-image-definition', 'boot', '-o', 'none'])
            self.run(['az', 'sig', 'delete', '-g', group, '--gallery-name', gallery, '-o', 'none'])
            self.run(['az', 'disk', 'delete', '-g', group, '-n', self.image, '--yes', '-o', 'none'])
