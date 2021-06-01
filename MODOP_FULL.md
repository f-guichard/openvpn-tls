Création des serveurs wireguard/openvpn sur GCP

#### 4.1.1 Installation du serveur OpenVPN

La création du VPC, des subnets, des règles de filtrage, la réservation de l'adresse ip publique et la machine gce peut se faire via terraform (voir plus bas) ou via l'IHM (ce qui a été fait en séance).

Une fois la machine GCE accessible via ssh, le serveur s'installe ainsi : 
```
wget -qO - https://as-repository.openvpn.net/as-repo-public.gpg | apt-key add -
wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg|apt-key add -
echo "deb http://as-repository.openvpn.net/as/debian bionic main">/etc/apt/sources.list.d/openvpn-as-repo.list
echo "deb http://build.openvpn.net/debian/openvpn/release/2.5 bionic main" > /etc/apt/sources.list.d/openvpn-aptrepo.list
apt update && apt -y install openvpn-as
passwd openvpn
```
#### 4.1.2 Build de la CA et génération des certificats OpenVPN

Il faut d'abord construire une autorité de certificats pour OpenVPN. Nous utiliserons EasyRSA. 

```
wget https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.8/EasyRSA-3.0.8.tgz
tar -xvzf EasyRSA-3.0.8.tgz 
cd EasyRSA-3.0.8/
sudo mv easyrsa /usr/local/bin
mkdir openvpn-ca
cd openvpn-ca/
easyrsa init-pki
cp ../EasyRSA-3.0.8/openssl-easyrsa.cnf /etc/openvpn/openvpn-ca/pki/openssl-easyrsa.cnf
easyrsa build-ca
ln -s /etc/openvpn/EasyRSA-3.0.8/x509-types /etc/openvpn/openvpn-ca/pki/x509-types
```


```
easyrsa gen-req OPENVPN_PUB_IP nopass
easyrsa import-req /etc/openvpn/openvpn-ca/pki/reqs/OPENVPN_PUB_IP.req OPENVPN_PUB_IP
easyrsa show-req OPENVPN_PUB_IP
easyrsa sign-req server OPENVPN_PUB_IP.req
easytls build-tls-crypt-v2-server OPENVPN_PUB_IP
```

:warning: A date, la passphrase de la clé privéé de la pki est XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

:warning: La clé privée du serveur est générée dans **/etc/openvpn/openvpn-ca/pki/private/OPENVPN_PUB_IP.key**

:warning: La certificat serveur est généré dans **/etc/openvpn/openvpn-ca/pki/issued/OPENVPN_PUB_IP.crt**

:warning: La clé pour le chiffrement des échanges TLS est dans /etc/openvpn/openvpn-ca/pki/easytls/tls-crypt.key

### 4.1.3 Mise en place du serveur Openvpn
#### 4.1.3.1 Configuration du serveur openvpn
La configuration stabilisée, à date, du serveur openvpn est décrite ci-après. Elle est stockée dans ***/etc/openvpn/server/server.conf***

Elle permet d'avoir une latence moyenne de 26ms sur des échanges tcp (tests de 18h). L'outil de mesure est ethr de Microsoft.

```
ca /etc/openvpn/openvpn-ca/pki/ca.crt
cert /etc/openvpn/openvpn-ca/pki/issued/OPENVPN_PUB_IP.crt
cipher AES-128-GCM
client-to-client
dev tun
dh none
ecdh-curve secp384r1
float
group nobody
ifconfig-pool-persist /var/log/openvpn/ipp.txt
keepalive 10 120
keepalive 20 300
key /etc/openvpn/openvpn-ca/pki/private/OPENVPN_PUB_IP.key # This file should be kept secret
local 172.23.0.2
max-clients 5
mssfix 1380
ncp-disable
opt-verify
persist-key
persist-tun
port 443
proto tcp
push "route 172.23.0.0 255.255.0.0"
remote-cert-tls client
server 192.168.201.0 255.255.255.240
socket-flags TCP_NODELAY
status /var/log/openvpn/openvpn-status.log
tls-cert-profile preferred
tls-ciphersuites TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
tls-crypt /etc/openvpn/openvpn-ca/pki/easytls/tls-crypt.key 0
tls-server
tls-version-min 1.3
tun-mtu 1420
user nobody
verb 3
verify-client-cert require
```

#### 4.1.3.2 Activation du service systemd-openvpn : 

```
root@openvpn-server:/etc/openvpn/server# systemctl start openvpn-server@server.service
root@openvpn-server:/etc/openvpn/server# systemctl status openvpn-server@server.service
● openvpn-server@server.service - OpenVPN service for server
   Loaded: loaded (/lib/systemd/system/openvpn-server@.service; disabled; vendor preset: enabled)
   Active: active (running) since Sun 2021-05-30 08:59:59 UTC; 10h ago
     Docs: man:openvpn(8)
           https://community.openvpn.net/openvpn/wiki/Openvpn24ManPage
           https://community.openvpn.net/openvpn/wiki/HOWTO
 Main PID: 27276 (openvpn)
   Status: "Initialization Sequence Completed"
    Tasks: 1 (limit: 1966)
   CGroup: /system.slice/system-openvpn\x2dserver.slice/openvpn-server@server.service
           └─27276 /usr/sbin/openvpn --status /run/openvpn-server/status-server.log --status-version 2 --suppress-timestamps --config server.conf

May 30 18:40:07 openvpn-server openvpn[27276]: open_vpn_home/90.44.97.60:43392 peer info: IV_PROTO=6
May 30 18:40:07 openvpn-server openvpn[27276]: open_vpn_home/90.44.97.60:43392 peer info: IV_LZ4=1
May 30 18:40:07 openvpn-server openvpn[27276]: open_vpn_home/90.44.97.60:43392 peer info: IV_LZ4v2=1
May 30 18:40:07 openvpn-server openvpn[27276]: open_vpn_home/90.44.97.60:43392 peer info: IV_LZO=1
May 30 18:40:07 openvpn-server openvpn[27276]: open_vpn_home/90.44.97.60:43392 peer info: IV_COMP_STUB=1
May 30 18:40:07 openvpn-server openvpn[27276]: open_vpn_home/90.44.97.60:43392 peer info: IV_COMP_STUBv2=1
May 30 18:40:07 openvpn-server openvpn[27276]: open_vpn_home/90.44.97.60:43392 peer info: IV_TCPNL=1
May 30 18:40:07 openvpn-server openvpn[27276]: open_vpn_home/90.44.97.60:43392 Outgoing Data Channel: Cipher 'AES-128-GCM' initialized with 128 bit key
May 30 18:40:07 openvpn-server openvpn[27276]: open_vpn_home/90.44.97.60:43392 Incoming Data Channel: Cipher 'AES-128-GCM' initialized with 128 bit key
May 30 18:40:07 openvpn-server openvpn[27276]: open_vpn_home/90.44.97.60:43392 Control Channel: TLSv1.3, cipher TLSv1.3 TLS_CHACHA20_POLY1305_SHA256, peer certificate: 2048 bit RSA, signature: RSA-SHA256
```

### 4.1.4 Mise en place du client Openvpn
#### 4.1.4.1 Configuration du serveur openvpn

La configuration en mirroir du client Openvpn est décrite ci-après.

Elle doit être stockée dans **/etc/openvpn/client/client.conf**

```
root@openvpn-client:/etc/openvpn/client# grep -E '^[A-Za-z0-9]' client.conf | sort -u
ca /etc/openvpn/client/certs/ca.crt
cert /etc/openvpn/client/certs/openvpn-client.crt
cipher AES-128-GCM
client
dev tun
ecdh-curve secp384r1
group nobody
key /etc/openvpn/client/certs/openvpn-client.key
mssfix 1360
ncp-disable
nobind
persist-key
persist-tun
proto tcp
remote OPENVPN_PUB_IP 443
remote-cert-tls server
resolv-retry infinite
socket-flags TCP_NODELAY
tls-cert-profile preferred
tls-ciphersuites TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
tls-client
tls-crypt /etc/openvpn/client/certs/tls-crypt.key 1
tls-version-min 1.3
tun-mtu 1420
user nobody
verb 3
```

:warning: **Cas particulier de ND1**

Si les échanges passent par un proxy http.

Il faut rajouter, pour ce cas particulier, la configuration suivante dans le fichier de configuration ***client.conf***: 
```
http-proxy IP_PROXY PORT_PROXY
```

#### 4.1.4.2 Activation du service systemd-openvpn : 
```
root@openvpn-client:/etc/openvpn/client# systemctl start openvpn-client@client.service
root@openvpn-client:/etc/openvpn/client# systemctl status openvpn-client@client.service
● openvpn-client@client.service - OpenVPN tunnel for client
     Loaded: loaded (/lib/systemd/system/openvpn-client@.service; disabled; vendor preset: enabled)
     Active: active (running) since Sun 2021-05-30 09:18:44 UTC; 10h ago
       Docs: man:openvpn(8)
             https://community.openvpn.net/openvpn/wiki/Openvpn24ManPage
             https://community.openvpn.net/openvpn/wiki/HOWTO
   Main PID: 1619 (openvpn)
     Status: "Initialization Sequence Completed"
      Tasks: 1 (limit: 1073)
     Memory: 1.4M
     CGroup: /system.slice/system-openvpn\x2dclient.slice/openvpn-client@client.service
             └─1619 /usr/sbin/openvpn --suppress-timestamps --nobind --config client.conf

May 30 18:40:07 openvpn-client openvpn[1619]: Control Channel: TLSv1.3, cipher TLSv1.3 TLS_CHACHA20_POLY1305_SHA256, peer certificate: 2048 bit RSA, signature: RSA-SHA256
May 30 19:36:15 openvpn-client openvpn[1619]: VERIFY OK: depth=1, CN=CA-OPENVPN-AEROFOUNDRY
May 30 19:36:15 openvpn-client openvpn[1619]: VERIFY KU OK
May 30 19:36:15 openvpn-client openvpn[1619]: Validating certificate extended key usage
May 30 19:36:15 openvpn-client openvpn[1619]: ++ Certificate has EKU (str) TLS Web Server Authentication, expects TLS Web Server Authentication
May 30 19:36:15 openvpn-client openvpn[1619]: VERIFY EKU OK
May 30 19:36:15 openvpn-client openvpn[1619]: VERIFY OK: depth=0, CN=OPENVPN_PUB_IP
May 30 19:36:15 openvpn-client openvpn[1619]: Outgoing Data Channel: Cipher 'AES-128-GCM' initialized with 128 bit key
May 30 19:36:15 openvpn-client openvpn[1619]: Incoming Data Channel: Cipher 'AES-128-GCM' initialized with 128 bit key
May 30 19:36:15 openvpn-client openvpn[1619]: Control Channel: TLSv1.3, cipher TLSv1.3 TLS_CHACHA20_POLY1305_SHA256, peer certificate: 2048 bit RSA, signature: RSA-SHA256
```
