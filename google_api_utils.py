import configparser
import contextlib
import json
import os
import pickle
import sqlite3
import urllib.parse
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Dict, Generator, List, Optional, Tuple, Union

import google.auth.credentials
import google.oauth2.credentials
import google.oauth2.service_account
import requests
from google.auth.transport.requests import Request
from google.oauth2.service_account import IDTokenCredentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import Resource, build

# Firestore imports
try:
    import firebase_admin.credentials
    import google.cloud.firestore
    from firebase_admin import delete_app, firestore, initialize_app
except ImportError:
    pass

# ========== 前知識 ==========
#
# Credentialsクラスは4つある。
# 1つはgoogle.auth.credentials.Credentialsクラスで、残る3つのクラスの継承関係上の祖先クラスにあたる。
#
# 残る3つは以下のとおり。
#
# * google.oauth2.credentials.Credentialsクラス：OAuth2認証によるクレデンシャル
# * google.oauth2.service_account.Credentialsクラス：サービスアカウント認証によるクレデンシャル。
#   アクセストークンが取得できる
# * google.oauth2.service_account.IDTokenCredentialsクラス：サービスアカウント認証によるクレデンシャル。
#   IDトークンが取得できる
#
# 3つのクラスは互いに独立しており継承上の関係はない。
#

# ========== クレデンシャル系 ==========


def _get_credentials_using_oauth_impl(
    client_secret_path: str,
    scopes: List[str],
    host: Optional[str] = None,
    port: Optional[int] = None,
    redirect_uri_trailing_slash: bool = True,
) -> Tuple[google.oauth2.credentials.Credentials, InstalledAppFlow]:
    flow = InstalledAppFlow.from_client_secrets_file(
        client_secret_path,
        scopes,
    )
    redirect_uri_trailing_slash = True
    if "redirect_uris" in flow.client_config:
        redirect_uris: List[str] = flow.client_config["redirect_uris"]
        if len(redirect_uris) > 0:
            redirect_uri = redirect_uris[0]
            parsed = urllib.parse.urlparse(redirect_uri)
            host = host or parsed.hostname
            port = port or parsed.port or 80
            redirect_uri_trailing_slash = redirect_uri.endswith("/")
    assert host is not None
    assert port is not None
    return (
        flow.run_local_server(
            host=host,
            port=port,
            redirect_uri_trailing_slash=redirect_uri_trailing_slash,
            access_type="offline",
            prompt="consent",
        ),
        flow,
    )


def get_credentials_using_oauth(  # noqa: CCR001
    client_secret_path: str,
    scopes: List[str],
    host: Optional[str] = None,
    port: Optional[int] = None,
    cache_path: Optional[str] = "./token.pickle",
) -> google.oauth2.credentials.Credentials:
    """OAuth2認証によるブラウザログインでCredentialsを取得する。

    トークンのキャッシュが有効な場合はキャッシュから取得する。
    キャッシュは存在するがトークンが無効な場合は自動でリフレッシュする。

    必要な準備＆ファイル

    1. Googleアカウント
    2. 「OAuth 同意画面」の設定完了: https://console.cloud.google.com/apis/credentials/consent
    3. 「OAuth 2.0 クライアント ID」から作成できるJSONファイル: https://console.cloud.google.com/apis/credentials

    Args:
        client_secret_path (str): 3.のファイルのパス
        scopes (List[str]): 認可を与えたいスコープ
        host: (Optional[str]): リダイレクト先のホスト名。省略時はclient_secretのredirect_urisの最初の要素から推定される。
        port: (Optional[str]): リダイレクト先のポート番号。省略時はclient_secretのredirect_urisの最初の要素から推定される。
        cache_path (Optional[str]): トークンのキャッシュファイルのパス。Noneを指定した場合はキャッシュを使用しない。

    Returns:
        google.oauth2.credentials.Credentials: Credentials
    """
    credentials: Optional[google.oauth2.credentials.Credentials] = None

    if cache_path and os.path.exists(cache_path):
        with open(cache_path, "rb") as token:
            credentials = pickle.load(token)
    if not credentials or not credentials.valid:
        if credentials and credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
        else:
            credentials, _ = _get_credentials_using_oauth_impl(
                client_secret_path,
                scopes,
                host,
                port,
            )
        if cache_path:
            with open(cache_path, "wb") as token:
                pickle.dump(credentials, token)

    return credentials


def get_credentials_with_raw_using_oauth(
    client_secret_path: str,
    scopes: List[str],
    host: Optional[str] = None,
    port: Optional[int] = None,
) -> Tuple[google.oauth2.credentials.Credentials, Dict[str, Any]]:
    """OAuth2認証によるブラウザログインでCredentialsと生データ（dict）を取得する。

    必要な準備＆ファイル

    1. Googleアカウント
    2. 「OAuth 同意画面」の設定完了: https://console.cloud.google.com/apis/credentials/consent
    3. 「OAuth 2.0 クライアント ID」から作成できるJSONファイル: https://console.cloud.google.com/apis/credentials

    Args:
        client_secret_path (str): 3.のファイルのパス
        scopes (List[str]): 認可を与えたいスコープ
        host: (Optional[str]): リダイレクト先のホスト名。省略時はclient_secretのredirect_urisの最初の要素から推定される。
        port: (Optional[str]): リダイレクト先のポート番号。省略時はclient_secretのredirect_urisの最初の要素から推定される。

    Returns:
        dict[str, Any]: Credentials
    """
    credentials, flow = _get_credentials_using_oauth_impl(
        client_secret_path,
        scopes,
        host,
        port,
    )
    return credentials, flow.oauth2session.token


def get_credentials_using_service_account(  # noqa: FNE008
    service_account_path_or_info: Union[str, Dict[str, Any]],
    scopes: List[str],
) -> google.oauth2.service_account.Credentials:
    """サービスアカウントのDictによってアクセストークンを返すCredentialsを取得する。

    必要な準備＆ファイル

    1. 「サービス アカウント」から作成できるJSONファイル: https://console.cloud.google.com/iam-admin/serviceaccounts

    Args:
        service_account_path_or_info (Union[str, Dict[str, Any]]):
            1.のファイルパス、1.のファイルをテキストとして読み込んだ結果、
            または1.のファイルをjson.loadした結果
        scopes (List[str]): 認可を与えたいスコープ

    Returns:
        google.oauth2.service_account.Credentials: Credentials
    """

    if isinstance(service_account_path_or_info, str):
        if os.path.exists(service_account_path_or_info):
            # as file
            credentials = google.oauth2.service_account.Credentials.from_service_account_file(
                service_account_path_or_info,
                scopes=scopes,
            )
        else:
            # as json
            service_account_info = json.loads(service_account_path_or_info)
            credentials = google.oauth2.service_account.Credentials.from_service_account_info(
                service_account_info,
                scopes=scopes,
            )
    else:
        credentials = google.oauth2.service_account.Credentials.from_service_account_info(
            service_account_path_or_info,
            scopes=scopes,
        )
    credentials.refresh(Request())
    return credentials


def get_credentials_using_google_application_credentials(  # noqa: FNE008
    scopes: List[str],
) -> google.oauth2.service_account.Credentials:
    """サービスアカウントによってアクセストークンを返すCredentialsを取得する。サービスアカウントは環境変数GOOGLE_APPLICATION_CREDENTIALから取得する。

    必要な準備＆ファイル

    1. 「サービス アカウント」から作成できるJSONファイル: https://console.cloud.google.com/iam-admin/serviceaccounts
    2. 環境変数GOOGLE_APPLICATION_CREDENTIALにサービスアカウントのJSONファイルのパス、またはJSONファイルの中身そのものを指定する

    Args:
        scopes (List[str]): 認可を与えたいスコープ

    Returns:
        google.oauth2.service_account.Credentials: Credentials
    """
    google_application_credentials = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", None)
    assert google_application_credentials, "GOOGLE_APPLICATION_CREDENTIALS is not set"

    return get_credentials_using_service_account(google_application_credentials, scopes)


def get_credentials_using_gcloud_auth_application_default_login(  # noqa: FNE008
    scopes: List[str],
) -> google.oauth2.credentials.Credentials:
    """あらかじめ `gcloud auth application-default login` しておいた作用を使ってCredentialsを取得する。

    必要な準備＆ファイル

    1. Googleアカウント
    2. `gcloud auth application-default login` しておく

    Args:
        scopes (List[str]): 認可を与えたいスコープ

    Returns:
        google.oauth2.credentials.Credentials: Credentials
    """
    path = os.path.expanduser("~/.config/gcloud/application_default_credentials.json")

    return google.oauth2.credentials.Credentials.from_authorized_user_file(path, scopes)


def get_credentials_using_gcloud_auth_login(  # noqa: FNE008
    scopes: List[str],
    configuration_name: Optional[str] = None,
) -> google.oauth2.credentials.Credentials:
    """あらかじめ `gcloud auth login` しておいた作用を使ってCredentialsを取得する。

    必要な準備＆ファイル

    1. Googleアカウント
    2. `gcloud auth login` しておく

    Args:
        scopes (List[str]): 認可を与えたいスコープ
        configuration_name (Optional[str]): gcloudの設定名。None指定時はgcloud上でアクティブな設定が適用される。
            （なお、設定は `gcloud config configurations` で確認できる。）

    Returns:
        google.oauth2.credentials.Credentials: Credentials
    """
    gcloud_path = os.path.expanduser("~/.config/gcloud")

    if configuration_name is None:
        with open(os.path.join(gcloud_path, "active_config")) as f:
            configuration_name = f.readline()

    config_path = os.path.join(gcloud_path, f"configurations/config_{configuration_name}")
    assert os.path.exists(config_path), f"{config_path} does not exist"

    config_parser = configparser.ConfigParser()
    _ = config_parser.read(config_path)
    account: str = config_parser["core"]["account"]

    credentials_db_path = os.path.join(gcloud_path, "credentials.db")
    with contextlib.closing(sqlite3.connect(credentials_db_path)) as con, contextlib.closing(
        con.cursor()
    ) as cur:
        _ = cur.execute(
            "SELECT value FROM credentials WHERE account_id = ?",
            (account,),
        )
        json_text = cur.fetchone()[0]
        credentials_obj: Dict[str, Any] = json.loads(json_text)

        return google.oauth2.credentials.Credentials.from_authorized_user_info(
            credentials_obj, scopes
        )


def get_id_token_credentials_using_service_account(
    service_account_path_or_info: Union[str, Dict[str, Any]],
    scopes: List[str],
) -> IDTokenCredentials:
    """サービスアカウントファイルによってIDトークンを返すCredentialsを取得する。

    必要な準備＆ファイル

    1. 「サービス アカウント」から作成できるJSONファイル: https://console.cloud.google.com/iam-admin/serviceaccounts

    Args:
        service_account_path_or_info (Union[str, Dict[str, Any]]): 1.のファイルパス、
            1.のファイルをテキストとして読み込んだ結果、または1.のファイルをjson.loadした結果
        scopes (List[str]): 認可を与えたいスコープ

    Returns:
        google.auth.credentials.Credentials: Credentials
    """

    if isinstance(service_account_path_or_info, str):
        if os.path.exists(service_account_path_or_info):
            # as file
            credentials = IDTokenCredentials.from_service_account_file(
                service_account_path_or_info,
                scopes=scopes,
            )
        else:
            # as json
            service_account_info = json.loads(service_account_path_or_info)
            credentials = IDTokenCredentials.from_service_account_info(
                service_account_info,
                scopes=scopes,
            )
    else:
        credentials = IDTokenCredentials.from_service_account_info(
            service_account_path_or_info,
            scopes=scopes,
        )
    credentials.refresh(Request())
    return credentials


# ========== トークン更新系（用途：Credentialを使わない更新を行う場合） ==========


def refresh_token(
    current_token: Dict[str, Any],
    client_id: str,
    client_secret: str,
) -> Dict[str, Any]:
    """トークンをリフレッシュする。

    必要な準備＆ファイル

    1. 「OAuth 同意画面」の設定完了: https://console.cloud.google.com/apis/credentials/consent
    2. 「OAuth 2.0 クライアント ID」から作成できるJSONファイル: https://console.cloud.google.com/apis/credentials

    Args:
        current_token (Dict[str, Any]): トークン情報。refresh_tokenフィールドが含まれていること。
        client_id (str): 2.のファイルから取得できるクライアントID
        client_secret (str): 2.のファイルから取得できるクライアントシークレット

    Returns:
        Dict[str, Any]: access_tokenフィールドを含むトークン情報。current_tokenと同等のフィールド全てが含まれているわけではないことに注意する。
    """
    refresh_token = current_token["refresh_token"]
    headers = {
        "Accept": "application/json",
    }

    data = {
        "client_secret": client_secret,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
    }
    response = requests.post(
        "https://www.googleapis.com/oauth2/v4/token",
        headers=headers,
        data=data,
    )
    response.raise_for_status()
    return response.json()


# ========== アクセストークン系（用途：Google APIを呼び出す） ==========


def get_access_token(
    credentials: google.auth.credentials.Credentials,
) -> str:
    if isinstance(
        credentials,
        (
            google.oauth2.credentials.Credentials,
            google.oauth2.service_account.Credentials,
        ),
    ):
        return credentials.token
    else:
        assert not isinstance(
            credentials, IDTokenCredentials
        ), f"credential type is {type(credentials).__name__}. Use get_credentials_using_service_account() instead."  # noqa: E501
        raise NotImplementedError(f'Unsupported credentials type: "{type(credentials)}"')


# ========== IDトークン系（用途：Cloud Functionsを呼び出す） ==========


def get_id_token(
    credentials: google.auth.credentials.Credentials,
) -> str:
    if isinstance(credentials, google.oauth2.credentials.Credentials):
        id_token = credentials.id_token
        assert id_token, "Maybe you forgot refresh token."
        return id_token
    elif isinstance(credentials, IDTokenCredentials):
        return credentials.token
    else:
        assert not isinstance(
            credentials, google.oauth2.service_account.Credentials
        ), f"credentials is {type(credentials).__name__}. Use get_id_token_credentials_using_service_account() instead."  # noqa: E501
        raise NotImplementedError(f'Unsupported credentials type: "{type(credentials)}"')


# ========== 汎用のGoogle API Client リソース ==========


def get_google_api_client_resource(
    credentials: google.auth.credentials.Credentials,
    service_name: str,
    version: str,
) -> Resource:
    """Google API Client リソースを取得する。

    Args:
        credentials (str): get_credentials_using_*関数で取得したCredentials
        scopes (List[str]): 認可を与えたいスコープ
        service_name (str): APIの名称
        version (str): APIのバージョン

    Returns:
        googleapiclient.discovery.Resource: Google API Client リソース
    """
    return build(
        service_name,
        version,
        credentials=credentials,
        static_discovery=False,
    )


# ========== Firestore ==========


@dataclass(frozen=True)
class _LocalCredential(firebase_admin.credentials.Base):  # type: ignore
    credentials: google.auth.credentials.Credentials

    def get_credential(self) -> google.auth.credentials.Credentials:
        return self.credentials


@contextmanager
def firestore_client(
    credentials: Optional[google.auth.credentials.Credentials],
    project_id: str,
) -> Generator[google.cloud.firestore.Client, None, None]:
    """Firestoreクライアントを取得する。

    以下のようにwith文をともなって使う。

    with firestore_client(credentials, project_id) as client:
        ここにコード

    Args:
        credentials (Optional[google.auth.credentials.Credentials]): Credentials。
            環境変数GOOGLE_APPLICATION_CREDENTIALSで指定されたサービスアカウントで認可したい場合はNoneを指定する。
            Cloud Functionsにおいて、デプロイされたCloud Functionsとひも付くサービスアカウントで認可したい場合もNoneを指定する。
            これら以外の方法で認可したい場合は、非NoneのCredentialsインスタンスを指定する。
        project_id (str): FirestoreのプロジェクトID

    Returns:
        google.cloud.firestore.Client: Firestoreクライアント
    """
    local_credentials = _LocalCredential(credentials) if credentials else None
    app = initialize_app(
        credential=local_credentials,
        options={"projectId": project_id},
    )
    try:
        client: google.cloud.firestore.Client = firestore.client(app)
        yield client
    finally:
        delete_app(app)
