import dataclasses
import typing


@dataclasses.dataclass
class OpenPorts:
    http: bool = False
    https: bool = False
    ssh: bool = False
    ftp: bool = False
    smtp: bool = False


@dataclasses.dataclass
class TLSCertificateTrust:
    name: str
    version: str
    validation_successful: bool


@dataclasses.dataclass
class TLSCertificate:
    certificate: str
    matches_hostname: bool
    is_ev: bool
    ocsp_must_staple: bool
    sct_count: int
    chain_in_order: bool
    has_sha1_signature: bool
    has_legacy_symantec_anchor: bool
    trust: typing.List[TLSCertificateTrust]


@dataclasses.dataclass
class TLSReport:
    ssl_2_0_cipher_suites: typing.List[str]
    ssl_3_0_cipher_suites: typing.List[str]
    tls_1_0_cipher_suites: typing.List[str]
    tls_1_1_cipher_suites: typing.List[str]
    tls_1_2_cipher_suites: typing.List[str]
    tls_1_3_cipher_suites: typing.List[str]
    supported_elliptic_curves: typing.List[str]
    supports_compression: bool
    supports_tls_1_3_early_data: bool
    downgrade_prevention: bool
    vulnerable_to_heartbleed: bool
    vulnerable_to_ccs_injection: bool
    vulnerable_to_client_renegotiation_dos: bool
    robot_result: str
    certificates: typing.List[TLSCertificate]


@dataclasses.dataclass
class Cookie:
    name: str
    secure: bool
    http_only: bool


@dataclasses.dataclass
class HeaderReport:
    value: str
    secure: bool


@dataclasses.dataclass
class HTTPReport:
    strict_transport_security: typing.Optional[HeaderReport]
    content_security_policy: typing.Optional[HeaderReport]
    permissions_policy: typing.Optional[HeaderReport]
    x_frame_options: typing.Optional[HeaderReport]
    x_content_type_options: typing.Optional[HeaderReport]
    referer_policy: typing.Optional[HeaderReport]
    cookies: typing.List[Cookie]
    cross_origin_embedder_policy: typing.Optional[HeaderReport]
    cross_origin_opener_policy: typing.Optional[HeaderReport]
    cross_origin_resource_policy: typing.Optional[HeaderReport]


@dataclasses.dataclass
class ApacheModStatusReport:
    server_info: bool
    server_status: bool


@dataclasses.dataclass
class Report:
    hidden_service: str
    open_ports: OpenPorts
    is_single_onion: bool = False
    tls_report: typing.Optional[TLSReport] = None
    http_report: typing.Optional[HTTPReport] = None
    apache_mod_status_report: typing.Optional[ApacheModStatusReport] = None
