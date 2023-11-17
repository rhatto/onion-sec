import socket
import typing
import cryptography.hazmat.primitives.serialization
import requests.adapters
import socks
import sslyze
import stem.control
import logging
from . import types


class ControlPort(stem.socket.ControlSocket):
    def __init__(self, address='127.0.0.1', port=9051, connect=True):
        super(ControlPort, self).__init__()
        self.address = address
        self.port = port

        if connect:
            self.connect()

    def _make_socket(self):
        try:
            control_socket = socket.create_connection((self.address, self.port), 30)
            return control_socket
        except socket.error as exc:
            raise stem.SocketError(exc)


class OnionSec:
    def __init__(self, proxy_addr: str, proxy_port: int, control_port: int, control_password: typing.Optional[str] = None):
        self.logger = logging.getLogger("onionsec")
        self.proxy_addr = proxy_addr
        self.proxy_port = proxy_port
        self.scanner = sslyze.Scanner()
        self.control_socket = ControlPort(proxy_addr, control_port)
        self.control_password = control_password

    @property
    def proxy_url(self):
        return f"socks5h://{self.proxy_addr}:{self.proxy_port}"

    def get_url(self, url: str):
        s = requests.Session()
        r = s.get(url, proxies={
            "http": self.proxy_url,
            "https": self.proxy_url
        }, verify=False)
        return r

    def get_socket(self, inet_family=socket.AF_INET):
        s = socks.socksocket(inet_family)
        s.set_proxy(socks.SOCKS5, self.proxy_addr, self.proxy_port, True)
        s.settimeout(30)
        return s

    def get_hs_descriptor(self, domain: str):
        self.logger.info(f"Fetching descriptor for {domain}")
        controller = stem.control.Controller(self.control_socket)
        controller.authenticate(self.control_password)
        desc = controller.get_hidden_service_descriptor(domain, timeout=30)
        if not desc:
            return None
        try:
            desc = stem.descriptor.hidden_service.HiddenServiceDescriptorV3(str(desc))
            inner = desc.decrypt(domain)
        except ValueError:
            return None
        return inner

    def test_tls(self, domain: str):
        self.logger.info(f"Testing TLS for {domain}")
        self.scanner.queue_scans([
            sslyze.ServerScanRequest(
                server_location=sslyze.ServerNetworkLocation(
                    hostname=domain,
                    port=443,
                    socks_proxy_settings=sslyze.SocksProxySettings(
                        hostname=self.proxy_addr,
                        port=self.proxy_port,
                        remote_dns=True
                    )
                ),
                network_configuration=sslyze.ServerNetworkConfiguration(
                    tls_server_name_indication=domain,
                    network_timeout=30,
                    network_max_retries=3
                ),
                scan_commands={
                    sslyze.ScanCommand.CERTIFICATE_INFO,
                    sslyze.ScanCommand.SSL_2_0_CIPHER_SUITES,
                    sslyze.ScanCommand.SSL_3_0_CIPHER_SUITES,
                    sslyze.ScanCommand.TLS_1_0_CIPHER_SUITES,
                    sslyze.ScanCommand.TLS_1_1_CIPHER_SUITES,
                    sslyze.ScanCommand.TLS_1_2_CIPHER_SUITES,
                    sslyze.ScanCommand.TLS_1_3_CIPHER_SUITES,
                    sslyze.ScanCommand.TLS_COMPRESSION,
                    sslyze.ScanCommand.TLS_1_3_EARLY_DATA,
                    sslyze.ScanCommand.OPENSSL_CCS_INJECTION,
                    sslyze.ScanCommand.TLS_FALLBACK_SCSV,
                    sslyze.ScanCommand.HEARTBLEED,
                    sslyze.ScanCommand.ROBOT,
                    sslyze.ScanCommand.SESSION_RENEGOTIATION,
                    sslyze.ScanCommand.ELLIPTIC_CURVES,
                }
            )
        ])
        res: sslyze.ServerScanResult = next(self.scanner.get_results())
        if not res.scan_result:
            return None
        return types.TLSReport(
            ssl_2_0_cipher_suites=list(map(
                lambda s: s.cipher_suite.name, res.scan_result.ssl_2_0_cipher_suites.result.accepted_cipher_suites
            )),
            ssl_3_0_cipher_suites=list(map(
                lambda s: s.cipher_suite.name, res.scan_result.ssl_3_0_cipher_suites.result.accepted_cipher_suites
            )),
            tls_1_0_cipher_suites=list(map(
                lambda s: s.cipher_suite.name, res.scan_result.tls_1_0_cipher_suites.result.accepted_cipher_suites
            )),
            tls_1_1_cipher_suites=list(map(
                lambda s: s.cipher_suite.name, res.scan_result.tls_1_1_cipher_suites.result.accepted_cipher_suites
            )),
            tls_1_2_cipher_suites=list(map(
                lambda s: s.cipher_suite.name, res.scan_result.tls_1_2_cipher_suites.result.accepted_cipher_suites
            )),
            tls_1_3_cipher_suites=list(map(
                lambda s: s.cipher_suite.name, res.scan_result.tls_1_3_cipher_suites.result.accepted_cipher_suites
            )),
            supported_elliptic_curves=list(map(
                lambda s: s.name, res.scan_result.elliptic_curves.result.supported_curves
            )) if res.scan_result.elliptic_curves.result.supported_curves else [],
            supports_compression=res.scan_result.tls_compression.result.supports_compression,
            supports_tls_1_3_early_data=res.scan_result.tls_1_3_early_data.result.supports_early_data,
            downgrade_prevention=res.scan_result.tls_fallback_scsv.result.supports_fallback_scsv,
            vulnerable_to_heartbleed=res.scan_result.heartbleed.result.is_vulnerable_to_heartbleed,
            vulnerable_to_ccs_injection=res.scan_result.openssl_ccs_injection.result.is_vulnerable_to_ccs_injection,
            vulnerable_to_client_renegotiation_dos=res.scan_result.session_renegotiation.result.is_vulnerable_to_client_renegotiation_dos,
            robot_result=str(res.scan_result.robot.result.robot_result.value),
            certificates=list(map(
                lambda c: types.TLSCertificate(
                    certificate=c.received_certificate_chain[0].public_bytes(
                        cryptography.hazmat.primitives.serialization.Encoding.PEM
                    ).decode(),
                    matches_hostname=c.leaf_certificate_subject_matches_hostname,
                    is_ev=c.leaf_certificate_is_ev,
                    ocsp_must_staple=c.leaf_certificate_has_must_staple_extension,
                    sct_count=c.leaf_certificate_signed_certificate_timestamps_count
                    if c.leaf_certificate_signed_certificate_timestamps_count else 0,
                    chain_in_order=c.received_chain_has_valid_order if c.received_chain_has_valid_order else False,
                    has_sha1_signature=c.verified_chain_has_sha1_signature if c.verified_chain_has_sha1_signature else False,
                    has_legacy_symantec_anchor=c.verified_chain_has_legacy_symantec_anchor if c.verified_chain_has_legacy_symantec_anchor else False,
                    trust=list(map(
                        lambda t: types.TLSCertificateTrust(
                            name=t.trust_store.name,
                            version=t.trust_store.version,
                            validation_successful=t.was_validation_successful
                        ), c.path_validation_results
                    ))
                ), res.scan_result.certificate_info.result.certificate_deployments
            ))
        )

    def test_open_port(self, domain: str, port: int):
        try:
            try:
                s = self.get_socket(socket.AF_INET6)
                s.connect((domain, port))
                return True
            except socks.ProxyConnectionError:
                s = self.get_socket(socket.AF_INET)
                s.connect((domain, port))
                return True
        except (socket.error, TimeoutError):
            return False

    def test_open_ports(self, domain: str):
        return types.OpenPorts(
            http=self.test_open_port(domain, 80),
            https=self.test_open_port(domain, 443),
            ssh=self.test_open_port(domain, 22),
            ftp=self.test_open_port(domain, 21),
            smtp=self.test_open_port(domain, 25),
        )

    def test_http_headers(self, target: str):
        self.logger.info(f"Testing HTTP headers for {target}")
        try:
            r = self.get_url(target)
        except requests.RequestException:
            return None
        headers = r.headers

        if "strict-transport-security" in headers:
            value = headers["strict-transport-security"]
            max_age = None
            for directive in value.split(";"):
                directive = directive.strip()
                if not directive:
                    continue

                if "max-age" in directive:
                    max_age = int(directive.split("max-age=")[1].strip())

            strict_transport_security = types.HeaderReport(
                value=headers["strict-transport-security"],
                secure=max_age is not None and max_age >= 10368000,
            )
        else:
            strict_transport_security = None

        if "content-security-policy" in headers:
            value = headers["content-security-policy"]
            secure = True
            for directive in value.split(";"):
                directive = directive.strip()
                if not directive:
                    continue

                if "unsafe-" in directive:
                    secure = False
                    break

            content_security_policy = types.HeaderReport(
                value=headers["content-security-policy"],
                secure=secure,
            )
        else:
            content_security_policy = None

        if "permissions-policy" in headers:
            permissions_policy = types.HeaderReport(
                value=headers["permissions-policy"],
                secure=True,
            )
        else:
            permissions_policy = None

        if "x-frame-options" in headers:
            value = headers["x-frame-options"].strip()
            x_frame_options = types.HeaderReport(
                value=value,
                secure=value == "DENY" or value == "SAMEORIGIN",
            )
        else:
            x_frame_options = None

        if "x-content-type-options" in headers:
            value = headers["x-content-type-options"].strip()
            x_content_type_options = types.HeaderReport(
                value=value,
                secure=value == "nosniff",
            )
        else:
            x_content_type_options = None

        if "referer-policy" in headers:
            value = headers["referer-policy"].strip()
            referer_policy = types.HeaderReport(
                value=value,
                secure=value != "unsafe-url",
            )
        else:
            referer_policy = None

        cookies = []
        if "set-cookie" in headers:
            for cookie in headers["set-cookie"].split(","):
                cookie = cookie.strip()
                if not cookie:
                    continue
                cookie = cookie.split(";")[0].strip()
                cookies.append(types.Cookie(
                    name=cookie.split("=")[0].strip(),
                    secure="Secure" in cookie,
                    http_only="HttpOnly" in cookie,
                ))

        if "cross-origin-embedder-policy" in headers:
            value = headers["cross-origin-embedder-policy"].strip()
            cross_origin_embedder_policy = types.HeaderReport(
                value=value,
                secure=not value.contains("unsafe-"),
            )
        else:
            cross_origin_embedder_policy = None

        if "cross-origin-opener-policy" in headers:
            value = headers["cross-origin-opener-policy"].strip()
            cross_origin_opener_policy = types.HeaderReport(
                value=value,
                secure=not value.contains("unsafe-"),
            )
        else:
            cross_origin_opener_policy = None

        if "cross-origin-resource-policy" in headers:
            cross_origin_resource_policy = types.HeaderReport(
                value=headers["cross-origin-resource-policy"],
                secure=True
            )
        else:
            cross_origin_resource_policy = None

        if "onion-location" in headers:
            onion_location = types.HeaderReport(
                value=headers["onion-location"],
                secure=True
            )
        else:
            onion_location = None

        return types.HTTPReport(
            strict_transport_security=strict_transport_security,
            content_security_policy=content_security_policy,
            permissions_policy=permissions_policy,
            x_frame_options=x_frame_options,
            x_content_type_options=x_content_type_options,
            referer_policy=referer_policy,
            cookies=cookies,
            cross_origin_embedder_policy=cross_origin_embedder_policy,
            cross_origin_opener_policy=cross_origin_opener_policy,
            cross_origin_resource_policy=cross_origin_resource_policy,
            onion_location=onion_location,
        )

    def test_apache_mod_status(self, target: str):
        self.logger.info(f"Testing Apache mod_status for {target}")
        try:
            server_info = self.get_url(f"{target}/server-info").status_code == 200
        except requests.RequestException:
            server_info = False
        try:
            server_status = self.get_url(f"{target}/server-status").status_code == 200
        except requests.RequestException:
            server_status = False
        return types.ApacheModStatusReport(
            server_info=server_info,
            server_status=server_status,
        )

    def run_report(self, domain: str):
        if not domain.endswith(".onion"):
            raise ValueError("Not an onion domain")
        raw_onion = domain.removesuffix(".onion").rsplit(".", 1)
        if len(raw_onion) == 2:
            raw_onion = raw_onion[1]
        else:
            raw_onion = raw_onion[0]

        desc = self.get_hs_descriptor(raw_onion)
        if not desc:
            return types.Report(
                hidden_service=domain,
                open_ports=types.OpenPorts(),
            )

        open_ports = self.test_open_ports(domain)
        if open_ports.http or open_ports.https:
            test_url = f"https://{domain}" if open_ports.https else f"http://{domain}"
            http_report = self.test_http_headers(test_url)
            apache_mod_status_report = self.test_apache_mod_status(test_url)
        else:
            http_report = None
            apache_mod_status_report = None
        tls_report = self.test_tls(domain) if open_ports.https else None

        return types.Report(
            hidden_service=domain,
            open_ports=open_ports,
            tls_report=tls_report,
            is_single_onion=desc.is_single_service,
            http_report=http_report,
            apache_mod_status_report=apache_mod_status_report,
        )



